#!/usr/bin/env python3
# Copyright 2025 Irreducible Inc.
"""
Benchmark runner for Monbijou CI/CD pipeline.
Handles multiple benchmarks with different threading and fusion configurations.
"""

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Any, Tuple
import argparse


# Benchmark configuration table
# Format: (name, example, args, enabled)
BENCHMARKS = [
    ("sha256", "sha256", "--max-len-bytes 65536", True),
    ("zklogin", "zklogin", "", True),
    ("base64", "base64", "--max-len 32768", False),
    ("skein512", "skein512", "--max-len 16384", False),
    ("keccak256", "keccak256", "--max-len 32768", False),
]

# Execution configurations: (name, env_vars)
CONFIGS = [
    ("multi-fusion", {"RAYON_NUM_THREADS": "0", "MONBIJOU_FUSION": "1"}),
    ("multi", {"RAYON_NUM_THREADS": "0"}),  # No fusion
    ("single-fusion", {"RAYON_NUM_THREADS": "1", "MONBIJOU_FUSION": "1"}),
    ("single", {"RAYON_NUM_THREADS": "1"}),  # No fusion
]


def run_command(cmd: str, env: Dict[str, str]) -> Tuple[int, str]:
    """Execute a command and return (exit_code, output)."""
    result = subprocess.run(
        cmd, shell=True, env={**os.environ, **env}, capture_output=True, text=True
    )
    output = result.stdout + result.stderr
    print(output)
    return result.returncode, output


def move_traces(benchmark_name: str, run_id: str, mode: str, run_num: int):
    """Move perfetto trace files to organized directory structure."""
    traces_dir = Path("perfetto_traces")
    target_dir = traces_dir / benchmark_name / run_id
    target_dir.mkdir(parents=True, exist_ok=True)

    # Find and move trace files
    for trace_file in traces_dir.glob("*.perfetto-trace"):
        new_name = f"{mode}-run{run_num}-{trace_file.name}"
        trace_file.rename(target_dir / new_name)


def run_benchmark(
    name: str, example: str, args: str, num_runs: int, run_id: str, log_dir: Path
) -> Dict[str, Any]:
    """Run a single benchmark with all configurations."""
    results = {"name": name, "runs": []}
    # Add -- separator before args
    command = f"cargo run --release --features perfetto --example {example} --"

    for config_name, env_vars in CONFIGS:
        print(f"\n{'=' * 60}")
        print(f"Running {name} ({config_name})")
        print(f"{'=' * 60}")

        log_file = log_dir / f"{name}_{config_name}.log"

        with open(log_file, "w") as log:
            for run in range(1, num_runs + 1):
                print(f"\n>>> {name} {config_name} run {run}/{num_runs}")

                # Add standard env vars
                env = {
                    **env_vars,
                    "RUSTFLAGS": "-C target-cpu=native",
                    "PERFETTO_TRACE_DIR": "./perfetto_traces",
                    "PERFETTO_PLATFORM_NAME": os.environ.get(
                        "PERFETTO_PLATFORM_NAME", "unknown"
                    ),
                }

                # Run the benchmark
                full_command = f"{command} {args}".strip() if args else command
                exit_code, output = run_command(full_command, env)

                # Log output
                log.write(f"=== Run {run}/{num_runs} ===\n")
                log.write(output)
                log.write("\n")

                # Move trace files
                move_traces(name, run_id, config_name, run)

                results["runs"].append(
                    {"config": config_name, "run": run, "exit_code": exit_code}
                )

                if exit_code != 0:
                    print(f"Warning: Benchmark failed with exit code {exit_code}")

    return results


def generate_stats(benchmarks: List[Tuple[str, str, str, bool]]) -> Path:
    """Generate circuit statistics for all benchmarks."""
    import re

    stats_file = Path("circuit_stats.md")

    with open(stats_file, "w") as f:
        f.write("## Circuit Statistics\n\n")

        for name, example, args, enabled in benchmarks:
            if not enabled:
                continue

            # Generate stats without fusion
            f.write(f"### {name} Circuit Statistics\n\n")
            f.write("#### Without Fusion\n")
            f.write("```\n")

            stat_args = f"stat {args}" if args else "stat"
            stat_cmd = f"cargo run --release --example {example} -- {stat_args} 2>&1"
            env = {"RUSTFLAGS": "-C target-cpu=native"}
            exit_code, output = run_command(stat_cmd, env)

            if exit_code == 0:
                # Remove ANSI escape codes and filter out compilation messages
                clean_output = re.sub(r"\x1b\[[0-9;]*m", "", output)
                # Only keep lines that look like statistics (not compilation output)
                stat_lines = []
                for line in clean_output.split("\n"):
                    if not any(
                        x in line
                        for x in ["Compiling", "Finished", "Running", "target/release"]
                    ):
                        if line.strip():
                            stat_lines.append(line)
                f.write("\n".join(stat_lines))
            else:
                f.write(f"Stats not available for {name}\n")

            f.write("\n```\n\n")

            # Generate stats with fusion
            f.write("#### With Fusion\n")
            f.write("```\n")

            env_fusion = {"RUSTFLAGS": "-C target-cpu=native", "MONBIJOU_FUSION": "1"}
            exit_code, output = run_command(stat_cmd, env_fusion)

            if exit_code == 0:
                # Remove ANSI escape codes and filter out compilation messages
                clean_output = re.sub(r"\x1b\[[0-9;]*m", "", output)
                stat_lines = []
                for line in clean_output.split("\n"):
                    if not any(
                        x in line
                        for x in ["Compiling", "Finished", "Running", "target/release"]
                    ):
                        if line.strip():
                            stat_lines.append(line)
                f.write("\n".join(stat_lines))
            else:
                f.write(f"Stats not available for {name} with fusion\n")

            f.write("\n```\n\n")

    return stats_file


def main():
    parser = argparse.ArgumentParser(description="Run Monbijou benchmarks")
    parser.add_argument(
        "--runs", type=int, default=1, help="Number of runs per configuration"
    )
    parser.add_argument("--run-id", required=True, help="Unique run identifier")
    parser.add_argument(
        "--generate-stats", action="store_true", help="Generate circuit statistics"
    )
    parser.add_argument("--filter", help="Run only specific benchmark by name")

    args = parser.parse_args()

    # Filter benchmarks
    benchmarks = [(n, e, a, en) for n, e, a, en in BENCHMARKS if en]
    if args.filter:
        benchmarks = [(n, e, a, en) for n, e, a, en in benchmarks if n == args.filter]

    if not benchmarks:
        print("No benchmarks to run")
        return

    print(f"Running {len(benchmarks)} benchmark(s):")
    for name, example, args_str, _ in benchmarks:
        print(f"  - {name:12} (example: {example}, args: {args_str or 'none'})")

    print(f"\nConfigurations: {', '.join(c[0] for c in CONFIGS)}")
    print(f"Runs per config: {args.runs}")

    # Setup directories
    log_dir = Path("benchmark_logs")
    log_dir.mkdir(exist_ok=True)
    Path("perfetto_traces").mkdir(exist_ok=True)

    # Run benchmarks
    all_results = []
    for name, example, args_str, _ in benchmarks:
        results = run_benchmark(
            name, example, args_str, args.runs, args.run_id, log_dir
        )
        all_results.append(results)

    # Generate stats if requested
    if args.generate_stats:
        stats_file = generate_stats(benchmarks)
        print(f"\nGenerated circuit statistics: {stats_file}")

    # Write results summary
    results_file = Path("benchmark_results.json")
    with open(results_file, "w") as f:
        json.dump(all_results, f, indent=2)

    print(f"\nBenchmark results saved to: {results_file}")

    # Check for failures
    failed = []
    for result in all_results:
        for run in result["runs"]:
            if run["exit_code"] != 0:
                failed.append(f"{result['name']} {run['config']} run {run['run']}")

    if failed:
        print("\nWarning: The following runs failed:")
        for f in failed:
            print(f"  - {f}")
        sys.exit(1)


if __name__ == "__main__":
    main()
