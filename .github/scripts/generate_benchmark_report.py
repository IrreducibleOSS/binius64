#!/usr/bin/env python3
"""Generate benchmark report for GitHub Actions summary from JSON summaries."""

import argparse
import json
import urllib.parse
from pathlib import Path
from typing import Dict, List, Any


def find_latest_benchmark_results_file(search_dir: Path = None) -> Path:
    """Find the latest benchmark-results JSON file."""
    if search_dir is None:
        search_dir = Path("benchmark_summaries")

    if not search_dir.exists():
        raise FileNotFoundError(f"Directory not found: {search_dir}")

    all_summaries = list(search_dir.glob("benchmark-results-*.json"))
    if not all_summaries:
        raise FileNotFoundError(f"No benchmark-results-*.json files found in {search_dir}")

    # Sort by modification time, newest first
    return max(all_summaries, key=lambda p: p.stat().st_mtime)


def generate_report_from_json(
    json_file: Path,
    branch_path: str = "",
    perfetto_host: str = "https://perfetto.irreducible.com",
) -> str:
    """Generate complete benchmark report from a JSON summary file."""
    output = []

    if not json_file.exists():
        output.append(f"JSON file not found: {json_file}")
        return "\n".join(output)

    with open(json_file) as f:
        data = json.load(f)

    if not data:
        output.append("No data in summary file.")
        return "\n".join(output)

    # Auto-detect machine name from the data
    machine = data[0].get("machine", "") if data else ""
    if machine:
        output.append(f"# Benchmark Report for {machine}")
        output.append("")

    # Generate metrics table
    output.append("## 📈 Benchmark Metrics")
    output.append("")

    # Group by circuit
    circuits: Dict[str, List[Dict[str, Any]]] = {}
    for entry in data:
        circuit = entry.get("circuit", "unknown")
        if circuit not in circuits:
            circuits[circuit] = []
        circuits[circuit].append(entry)

    for circuit in sorted(circuits.keys()):
        output.append(f"### {circuit}")

        # Show parameters if available
        if params := circuits[circuit][0].get("parameters"):
            output.append(f"**Parameters:** {params}")

        output.append("")
        output.append(
            "| Config | Witness (ms) | Prove (ms) | Verify (ms) | Proof Size (bytes) | Traces |"
        )
        output.append(
            "|--------|--------------|------------|-------------|-------------------|---------|"
        )

        # Sort for consistent display
        entries = sorted(
            circuits[circuit],
            key=lambda x: (x.get("threading", "single"), not x.get("fusion", False)),
        )

        for entry in entries:
            config = entry.get("threading", "single")
            if entry.get("fusion"):
                config += "-fusion"

            witness = entry.get("avg_witness_ms", 0)
            prove = entry.get("avg_prove_ms", 0)
            verify = entry.get("avg_verify_ms", 0)
            proof_size = entry.get("avg_proof_size_bytes", 0)

            # Generate trace links for this entry
            trace_files = entry.get("trace_files", [])
            trace_links = []
            if trace_files:
                for i, trace_path in enumerate(trace_files, 1):
                    # Generate Perfetto URLs with provided branch path
                    s3_key = f"traces/binius64/{branch_path}/{trace_path}"
                    trace_url = f"{perfetto_host}/{s3_key}"
                    encoded_url = urllib.parse.quote_plus(trace_url)
                    perfetto_ui_url = f"{perfetto_host}/#!/?url={encoded_url}"
                    trace_links.append(f"[{i}]({perfetto_ui_url})")

            trace_links_str = " ".join(trace_links) if trace_links else "—"

            output.append(
                f"| {config} | {witness:.2f} | {prove:.2f} | {verify:.2f} | {proof_size:.0f} | {trace_links_str} |"
            )

        output.append("")

    return "\n".join(output)


def main():
    parser = argparse.ArgumentParser(
        description="Generate benchmark report from JSON summary file"
    )
    parser.add_argument(
        "--json-file",
        type=Path,
        default=None,
        help="Path to benchmark-results JSON file (auto-detects latest if not provided)",
    )
    parser.add_argument(
        "--summaries-dir",
        type=Path,
        default=Path("benchmark_summaries"),
        help="Directory to search for benchmark-results JSON files (default: benchmark_summaries)",
    )
    parser.add_argument(
        "--branch-path",
        type=str,
        required=True,
        help="S3 branch path for Perfetto links (e.g., 'main' or 'branch-feature')",
    )
    parser.add_argument(
        "--perfetto-host",
        type=str,
        default="https://perfetto.irreducible.com",
        help="Perfetto host URL",
    )
    parser.add_argument(
        "--output", type=Path, default=None, help="Output file (default: stdout)"
    )

    args = parser.parse_args()

    # Determine which JSON file to use
    if args.json_file:
        json_file = args.json_file
        print(f"DEBUG: Using specified JSON file: {json_file}")
    else:
        try:
            json_file = find_latest_benchmark_results_file(args.summaries_dir)
            print(f"DEBUG: Auto-detected JSON file: {json_file}")
        except FileNotFoundError as e:
            print(f"DEBUG: Error finding JSON file: {e}")
            return 1

    # Generate the report
    try:
        report = generate_report_from_json(
            json_file, args.branch_path, args.perfetto_host
        )
    except Exception as e:
        print(f"Error generating report: {e}")
        return 1

    # Output the report
    if args.output:
        args.output.write_text(report)
        print(f"Report written to {args.output}")
    else:
        print(report)

    return 0


if __name__ == "__main__":
    main()
