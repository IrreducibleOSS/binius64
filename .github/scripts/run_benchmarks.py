#!/usr/bin/env python3
"""Benchmark runner for Binius64 with perfetto tracing support."""

import argparse
import json
import os
import platform
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, NamedTuple

from perfetto.trace_processor import TraceProcessor
import socket


class Example(NamedTuple):
    """Benchmark example configuration."""

    name: str
    example: str
    args: str = ""


class OperationTiming(NamedTuple):
    """Timing data for a single operation."""

    name: str
    duration_ns: int

    @property
    def duration_ms(self) -> float:
        return self.duration_ns / 1_000_000


@dataclass
class TraceMetrics:
    """Metrics extracted from a single trace file."""

    iteration: int
    witness_ms: float = 0
    prove_ms: float = 0
    verify_ms: float = 0
    proof_size_bytes: int = 0
    trace_file: str = ""

    @classmethod
    def from_operations(
        cls, iteration: int, operations: List[OperationTiming], trace_file: str = ""
    ):
        # The OperationTiming.name field now contains the operation name from debug.operation if available
        # We already handled this in extract_trace_metrics
        ops = {op.name.lower(): op.duration_ms for op in operations}

        # Look for operations - the actual names from debug.operation field or span names
        # The debug.operation values are: witness_generation, prove, verify
        witness_ms = ops.get("witness_generation", 0) or ops.get(
            "generating witness", 0
        )
        prove_ms = ops.get("prove", 0) or ops.get("proving", 0)
        verify_ms = (
            ops.get("verify", 0)
            or ops.get("verification", 0)
            or ops.get("verifying", 0)
        )

        return cls(
            iteration=iteration,
            witness_ms=witness_ms,
            prove_ms=prove_ms,
            verify_ms=verify_ms,
            trace_file=trace_file,
        )


@dataclass
class AggregateMetrics:
    """Aggregated metrics across multiple runs."""

    avg_witness_ms: float
    avg_prove_ms: float
    avg_verify_ms: float
    avg_proof_size_bytes: float

    @classmethod
    def from_traces(cls, traces: List[TraceMetrics]):
        if not traces:
            return cls(0, 0, 0, 0)

        n = len(traces)
        return cls(
            avg_witness_ms=sum(t.witness_ms for t in traces) / n,
            avg_prove_ms=sum(t.prove_ms for t in traces) / n,
            avg_verify_ms=sum(t.verify_ms for t in traces) / n,
            avg_proof_size_bytes=sum(t.proof_size_bytes for t in traces) / n,
        )


@dataclass
class BenchmarkResult:
    """Complete benchmark result."""

    benchmark: str
    parameters: str = ""
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    git_commit: str = ""
    git_commit_time: str = ""
    git_branch: str = ""
    env_os: str = field(default_factory=lambda: platform.system().lower())
    env_arch: str = field(default_factory=lambda: platform.machine())
    env_cpu_count: int = field(default_factory=lambda: os.cpu_count() or 1)
    iterations: int = 0
    log_inv_rate: int = 1
    timings: dict = field(default_factory=dict)


# Benchmark configurations
EXAMPLES = [
    Example("sha256", "sha256", "--max-len-bytes 65536"),
    Example("sha512", "sha512", "--max-len-bytes 98304"),
    Example("keccak", "keccak", "--n-permutations 1500"),
    Example("ethsign", "ethsign", "--n-signatures 6 --max-msg-len-bytes 128"),
    Example("blake2s", "blake2s", "--max-bytes 131072"),
]

CONFIGS = {
    "single": {"RAYON_NUM_THREADS": "1", "PERFETTO_TRACE_THREADS": "single-threaded"},
    "single-fusion": {
        "RAYON_NUM_THREADS": "1",
        "MONBIJOU_FUSION": "1",
        "PERFETTO_TRACE_THREADS": "single-threaded",
        "PERFETTO_TRACE_FUSION": "fusion",
    },
    "multi": {"RAYON_NUM_THREADS": "0", "PERFETTO_TRACE_THREADS": "multi-threaded"},
    "multi-fusion": {
        "RAYON_NUM_THREADS": "0",
        "MONBIJOU_FUSION": "1",
        "PERFETTO_TRACE_THREADS": "multi-threaded",
        "PERFETTO_TRACE_FUSION": "fusion",
    },
}


def run_command(cmd: str, env: Dict[str, str]) -> int:
    """Execute a command with given environment."""
    full_env = {"RUSTFLAGS": "-C target-cpu=native", **os.environ, **env}
    print(f"  Command: {cmd}")
    return subprocess.run(cmd, shell=True, env=full_env).returncode


def normalize_trace_dir_path(trace_dir: Path) -> str:
    """Normalize trace directory path by removing perfetto_traces/ prefix if present."""
    trace_path_str = str(trace_dir)
    if "perfetto_traces/" in trace_path_str:
        return trace_path_str.split("perfetto_traces/", 1)[1]
    return trace_path_str


def get_trace_dir() -> Optional[Path]:
    """Read the last perfetto trace directory."""
    trace_path_file = Path(".last_perfetto_trace_path")
    if not trace_path_file.exists():
        return None

    trace_path = Path(trace_path_file.read_text().strip())
    if not trace_path.exists():
        return None

    return trace_path.parent if trace_path.is_file() else trace_path


def extract_trace_metrics(trace_file: Path) -> Optional[TraceMetrics]:
    """Extract metrics from a perfetto trace file."""
    # Add file existence check
    if not trace_file.exists():
        print(f"    Warning: Trace file does not exist: {trace_file.name}")
        return None

    try:
        tp = TraceProcessor(trace=str(trace_file))

        # Query for operation timings
        operation_query = """
            SELECT
                s.name,
                s.dur as duration_ns,
                a.string_value as operation
            FROM slice s
            LEFT JOIN args a ON s.arg_set_id = a.arg_set_id AND a.key = 'debug.operation'
            WHERE s.category = 'operation'
            ORDER BY s.ts
        """

        result = tp.query(operation_query)
        # Use the operation field if available, otherwise fall back to name
        operations = [
            OperationTiming(
                row.operation if row.operation else row.name, row.duration_ns
            )
            for row in result
        ]

        # Query for proof size from metrics events
        proof_size_query = """
            SELECT
                a.int_value as proof_size_bytes
            FROM slice s
            JOIN args a ON s.arg_set_id = a.arg_set_id
            WHERE s.name = 'proof_size' AND a.key = 'debug.proof_size_bytes'
            LIMIT 1
        """

        proof_result = list(tp.query(proof_size_query))
        proof_size_bytes = (
            proof_result[0].proof_size_bytes if len(proof_result) > 0 else 0
        )

        # Extract iteration from filename
        iteration = 1
        try:
            if "-iter" in trace_file.name:
                filename_parts = trace_file.name.split("-iter")
                if len(filename_parts) > 1:
                    iter_part = filename_parts[1].split("-")[0]
                    if iter_part.isdigit():
                        iteration = int(iter_part)
        except (ValueError, IndexError):
            pass  # Default to iteration 1

        metrics = TraceMetrics.from_operations(iteration, operations, trace_file.name)
        metrics.proof_size_bytes = proof_size_bytes
        return metrics

    except Exception as e:
        print(f"    Error processing {trace_file.name}: {e}")
        return None


def get_git_info() -> dict:
    """Get git information for the current repository."""
    try:

        def run(cmd):
            return subprocess.run(cmd, capture_output=True, text=True).stdout.strip()

        commit = run(["git", "rev-parse", "HEAD"])
        return {
            "commit": commit[:7],
            "commit_time": run(["git", "show", "-s", "--format=%cI", commit]),
            "branch": run(["git", "rev-parse", "--abbrev-ref", "HEAD"]),
        }
    except Exception:
        return {"commit": "", "commit_time": "", "branch": ""}


def post_process_traces(
    trace_dir: Path, example_name: str = "", example_args: str = ""
) -> Optional[BenchmarkResult]:
    """Post-process perfetto traces in a directory."""
    print(f"  Processing traces in {trace_dir}")

    trace_files = list(trace_dir.glob("*.perfetto-trace"))
    if not trace_files:
        print("    No trace files found")
        return None

    print(f"    Found {len(trace_files)} trace files")

    # Extract metrics
    trace_metrics = sorted(
        filter(None, (extract_trace_metrics(f) for f in trace_files)),
        key=lambda x: x.iteration,
    )

    if not trace_metrics:
        print("    No valid metrics extracted")
        return None

    # Use actual command arguments instead of extracting from filename
    parameters = example_args

    # Build result
    aggregate = AggregateMetrics.from_traces(trace_metrics)
    git_info = get_git_info()

    result = BenchmarkResult(
        benchmark=example_name or "unknown",
        parameters=parameters,
        git_commit=git_info["commit"],
        git_commit_time=git_info["commit_time"],
        git_branch=git_info["branch"],
        iterations=len(trace_metrics),
        timings={
            "aggregate": {
                "avg_witness_ms": aggregate.avg_witness_ms,
                "avg_prove_ms": aggregate.avg_prove_ms,
                "avg_verify_ms": aggregate.avg_verify_ms,
                "avg_proof_size_bytes": aggregate.avg_proof_size_bytes,
            },
            "all_runs": [
                {
                    "iteration": t.iteration,
                    "witness_ms": t.witness_ms,
                    "prove_ms": t.prove_ms,
                    "verify_ms": t.verify_ms,
                    "proof_size_bytes": t.proof_size_bytes,
                    "trace_file": t.trace_file,
                }
                for t in trace_metrics
            ],
        },
    )

    # Save metrics to trace directory (critical missing feature)
    metrics_file = trace_dir / "metrics.json"
    # Store trace_dir relative to perfetto_traces (e.g., "sha256/20250903-032211-80a3f42")
    trace_dir_relative = normalize_trace_dir_path(trace_dir)
    result_dict = {**asdict(result), "trace_dir": trace_dir_relative}
    metrics_file.write_text(json.dumps(result_dict, indent=2))
    print(f"    Metrics saved to {metrics_file}")

    return result


def create_summary_entries(
    example_name: str, results: List[dict], machine_id: str
) -> List[dict]:
    """Create flat summary entries for an example across all configurations."""
    summary_entries = []
    git_info = get_git_info()
    timestamp = datetime.now(timezone.utc).isoformat()

    # Create platform identifier
    platform_id = f"{platform.system().lower()}-{platform.machine()}"

    for r in results:
        if r.get("metrics") and hasattr(r["metrics"], "timings"):
            config_name = r["config"]
            aggregate = r["metrics"].timings.get("aggregate", {})
            parameters = (
                r["metrics"].parameters if hasattr(r["metrics"], "parameters") else ""
            )

            # Get trace_dir from metrics - it's stored as an attribute
            trace_dir = getattr(r["metrics"], "trace_dir", "")

            # Get individual trace file paths from all_runs
            trace_files = []
            if "all_runs" in r["metrics"].timings:
                for run in r["metrics"].timings["all_runs"]:
                    if "trace_file" in run and run["trace_file"]:
                        # Construct the full relative path
                        if trace_dir:
                            trace_path = f"{trace_dir}/{run['trace_file']}"
                        else:
                            trace_path = run["trace_file"]
                        trace_files.append(trace_path)

            # Parse config name to extract threading and fusion settings
            is_multi = "multi" in config_name
            has_fusion = "fusion" in config_name

            entry = {
                # Core metrics
                "avg_witness_ms": aggregate.get("avg_witness_ms", 0),
                "avg_prove_ms": aggregate.get("avg_prove_ms", 0),
                "avg_verify_ms": aggregate.get("avg_verify_ms", 0),
                "avg_proof_size_bytes": aggregate.get("avg_proof_size_bytes", 0),
                # Configuration
                "fusion": has_fusion,
                "threading": "multi" if is_multi else "single",
                # Identification
                "machine": machine_id,
                "circuit": example_name,  # Using "circuit" for consistency
                "parameters": parameters,
                # Git info
                "git_commit": git_info["commit"],
                "git_commit_time": git_info["commit_time"],
                "git_branch": git_info["branch"],
                # Environment
                "platform": platform_id,
                # Timing
                "run_timestamp": timestamp,
                "iterations": r["metrics"].iterations
                if hasattr(r["metrics"], "iterations")
                else r.get("repeat", 5),
                # Trace paths
                "trace_files": trace_files,
                "trace_dir": trace_dir,
            }
            summary_entries.append(entry)

    return summary_entries


def run_benchmark(
    example: Example, config_name: str, env: Dict[str, str], repeat: int = 5
) -> dict:
    """Run a single benchmark configuration."""
    print(f"\n{'=' * 60}")
    print(f"Running {example.name} ({config_name})")
    print(f"{'=' * 60}")

    # Clean up old trace path
    Path(".last_perfetto_trace_path").unlink(missing_ok=True)

    # Build and run command
    cmd = f"cargo run --release --features perfetto --example {example.example} -- --repeat {repeat}"
    if example.args:
        cmd += f" {example.args}"

    exit_code = run_command(cmd, env)

    # Process traces
    trace_dir = get_trace_dir()
    metrics = (
        post_process_traces(trace_dir, example.name, example.args)
        if trace_dir
        else None
    )

    if not metrics:
        print("  Warning: Could not find trace directory")

    # Add trace_dir to metrics if available
    if metrics and trace_dir:
        metrics.trace_dir = normalize_trace_dir_path(trace_dir)

    return {
        "example": example.name,
        "config": config_name,
        "exit_code": exit_code,
        "repeat": repeat,
        "metrics": metrics,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Run Binius64 benchmarks with perfetto tracing"
    )
    parser.add_argument(
        "examples", nargs="*", help="Specific examples to run (default: all)"
    )
    parser.add_argument(
        "--repeat", type=int, default=5, help="Number of iterations (default: 5)"
    )
    parser.add_argument("--list", action="store_true", help="List available examples")
    parser.add_argument(
        "--extract-only",
        type=str,
        metavar="PATH",
        help="Extract metrics from existing traces",
    )

    args = parser.parse_args()

    # Handle special modes
    if args.list:
        print("Available examples:")
        for ex in EXAMPLES:
            print(f"  {ex.name:12} (example: {ex.example}, args: {ex.args or 'none'})")
        return 0

    if args.extract_only:
        trace_dir = Path(args.extract_only)
        if not trace_dir.is_dir():
            print(f"Error: Not a directory: {trace_dir}")
            return 1
        post_process_traces(trace_dir)
        return 0

    # Select examples
    examples = EXAMPLES
    if args.examples:
        examples = [ex for ex in EXAMPLES if ex.name in args.examples]
        if not examples:
            print("Error: No matching examples found. Use --list to see available.")
            return 1

    # Display configuration
    print(f"Running {len(examples)} example(s) with {len(CONFIGS)} configurations")
    print(f"Iterations per benchmark: {args.repeat}\n")
    print("Examples:", ", ".join(ex.name for ex in examples))
    print("Configurations:", ", ".join(CONFIGS.keys()))

    # Setup output directory
    summaries_dir = Path("benchmark_summaries")
    summaries_dir.mkdir(exist_ok=True)

    # Run benchmarks
    # Add time to the filename for uniqueness
    datetime_str = datetime.now().strftime("%Y%m%d-%H%M%S")

    # Respect PERFETTO_PLATFORM_NAME if set, otherwise use hostname
    platform_name = os.environ.get("PERFETTO_PLATFORM_NAME")
    if platform_name:
        # Use platform name from environment (e.g., "c7i-16xlarge" in CI)
        machine_id = platform_name
    else:
        # Use hostname for local runs - simplify it
        hostname = socket.gethostname().split(".")[0]
        # Further simplify hostname - remove common prefixes/suffixes
        if hostname.lower().endswith("-pro"):
            hostname = hostname[:-4]
        if hostname.lower().endswith("-macbook"):
            hostname = hostname[:-8]
        machine_id = hostname

    all_entries = []
    failed_runs = []

    for example in examples:
        results = []
        example_failed = False

        # Run all configurations for this example
        for config_name, env in CONFIGS.items():
            result = run_benchmark(example, config_name, env, args.repeat)
            results.append(result)

            if result["exit_code"] != 0:
                failed_runs.append(f"{example.name} ({config_name})")
                example_failed = True

        # Save summary immediately after finishing all configs for this example
        if not example_failed:
            # Create flat entries for this example
            entries = create_summary_entries(example.name, results, machine_id)
            if entries:
                all_entries.extend(entries)

                # Sort all entries by git commit time (newest first)
                # Handle cases where git_commit_time might be empty or invalid
                all_entries.sort(
                    key=lambda x: x.get("git_commit_time") or "", reverse=True
                )

                # Save individual example summary as flat array
                # Simplified filename: example-datetime-machine
                filename = f"{example.name}-{datetime_str}-{machine_id}.json"
                example_only_entries = [
                    e for e in entries
                ]  # Just this example's entries
                (summaries_dir / filename).write_text(
                    json.dumps(example_only_entries, indent=2)
                )
                print(f"\n  Saved {example.name} summary: {summaries_dir / filename}")

                # Update and save overall summary with all examples completed so far
                overall_file = f"benchmark-results-{datetime_str}-{machine_id}.json"
                (summaries_dir / overall_file).write_text(
                    json.dumps(all_entries, indent=2)
                )
                print(f"  Updated overall summary: {summaries_dir / overall_file}")

    # Final report
    if failed_runs:
        print(f"\nFailed runs: {', '.join(failed_runs)}")
        return 1

    print(f"\n{'=' * 60}")
    print(f"All benchmarks completed! Summaries in: {summaries_dir}")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
