#!/usr/bin/env python3
"""
Build Benchmark Tool

Benchmark different Rust build configurations to measure resource usage and analyze results.
This helps determine the cost of various features like release mode, LTO, etc.
"""

import subprocess
import time
import psutil
import os
import sys
import json
import argparse
import csv
from datetime import datetime
from pathlib import Path
import shutil
import signal
import threading
from typing import Dict, List, Optional, Tuple

class BuildBenchmarker:
    def __init__(self, output_file="build_benchmark_results.json"):
        self.output_file = output_file
        self.results = []
        self.current_process = None
        self.max_memory = 0
        self.monitoring = False
        
    def monitor_resources(self, pid):
        """Monitor CPU and memory usage of a process and its children."""
        self.monitoring = True
        self.max_memory = 0
        
        while self.monitoring:
            try:
                parent = psutil.Process(pid)
                # Get all child processes
                children = parent.children(recursive=True)
                all_processes = [parent] + children
                
                total_memory = 0
                for proc in all_processes:
                    try:
                        total_memory += proc.memory_info().rss
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                
                self.max_memory = max(self.max_memory, total_memory)
                time.sleep(0.1)  # Sample every 100ms
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                break
    
    def run_cargo_command(self, cmd, env_vars=None, timeout=1800):
        """Run a cargo command and measure its resource usage."""
        # Clean before each build to ensure consistent measurements
        print("Cleaning previous build artifacts...")
        subprocess.run(["cargo", "clean"], check=True)
        
        # Prepare environment
        env = os.environ.copy()
        if env_vars:
            env.update(env_vars)
        
        # Start the process
        start_time = time.time()
        process = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.current_process = process
        
        # Start monitoring thread
        monitor_thread = threading.Thread(target=self.monitor_resources, args=(process.pid,))
        monitor_thread.start()
        
        try:
            stdout, stderr = process.communicate(timeout=timeout)
            returncode = process.returncode
            success = returncode == 0
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
            returncode = -1
            success = False
            print(f"Command timed out after {timeout} seconds")
        finally:
            self.monitoring = False
            monitor_thread.join()
            
        end_time = time.time()
        duration = end_time - start_time
        
        return {
            "success": success,
            "duration_seconds": duration,
            "max_memory_mb": self.max_memory / (1024 * 1024),
            "returncode": returncode,
            "stdout": stdout.decode('utf-8', errors='ignore'),
            "stderr": stderr.decode('utf-8', errors='ignore')
        }
    
    def benchmark_configuration(self, name, cmd, env_vars=None, runs=1):
        """Benchmark a specific configuration multiple times."""
        print(f"\n{'='*60}")
        print(f"Benchmarking: {name}")
        print(f"Command: {' '.join(cmd)}")
        if env_vars:
            print(f"Environment: {env_vars}")
        print(f"{'='*60}")
        
        results = []
        for i in range(runs):
            print(f"\nRun {i+1}/{runs}...")
            result = self.run_cargo_command(cmd, env_vars)
            results.append(result)
            
            if result["success"]:
                print(f"✓ Completed in {result['duration_seconds']:.1f}s, "
                      f"max memory: {result['max_memory_mb']:.1f} MB")
            else:
                print(f"✗ Failed with code {result['returncode']}")
                if runs > 1:
                    print("Skipping remaining runs due to failure")
                    break
        
        # Calculate averages if multiple successful runs
        successful_runs = [r for r in results if r["success"]]
        if successful_runs:
            avg_duration = sum(r["duration_seconds"] for r in successful_runs) / len(successful_runs)
            avg_memory = sum(r["max_memory_mb"] for r in successful_runs) / len(successful_runs)
            max_memory = max(r["max_memory_mb"] for r in successful_runs)
        else:
            avg_duration = avg_memory = max_memory = 0
        
        return {
            "name": name,
            "command": " ".join(cmd),
            "env_vars": env_vars or {},
            "runs": len(results),
            "successful_runs": len(successful_runs),
            "avg_duration_seconds": avg_duration,
            "avg_memory_mb": avg_memory,
            "max_memory_mb": max_memory,
            "individual_runs": results
        }
    
    def run_benchmarks(self, configs, runs=1):
        """Run all benchmark configurations."""
        machine_info = {
            "hostname": os.uname().nodename,
            "platform": sys.platform,
            "cpu_count": psutil.cpu_count(),
            "total_memory_gb": psutil.virtual_memory().total / (1024**3),
            "rust_version": subprocess.check_output(["rustc", "--version"]).decode().strip(),
            "timestamp": datetime.now().isoformat()
        }
        
        print(f"\nMachine Info:")
        print(f"  Hostname: {machine_info['hostname']}")
        print(f"  CPUs: {machine_info['cpu_count']}")
        print(f"  Memory: {machine_info['total_memory_gb']:.1f} GB")
        print(f"  Rust: {machine_info['rust_version']}")
        
        results = {
            "machine_info": machine_info,
            "configurations": []
        }
        
        for config in configs:
            result = self.benchmark_configuration(
                config["name"],
                config["cmd"],
                config.get("env_vars"),
                runs
            )
            results["configurations"].append(result)
            
            # Save after each benchmark in case of crashes
            self.save_results(results)
        
        return results
    
    def save_results(self, results):
        """Save results to JSON file."""
        with open(self.output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\nResults saved to {self.output_file}")
    
    def compare_results(self, results):
        """Generate a comparison summary of the results."""
        print(f"\n{'='*80}")
        print("SUMMARY")
        print(f"{'='*80}")
        
        configs = results["configurations"]
        
        # Find baseline (debug build)
        baseline = next((c for c in configs if c["name"] == "cargo test --no-run"), None)
        if not baseline or baseline["successful_runs"] == 0:
            baseline = configs[0] if configs else None
        
        if not baseline:
            print("No successful builds to compare")
            return
        
        print(f"\n{'Configuration':<50} {'Time (s)':<12} {'Memory (MB)':<12} {'vs Baseline':<20}")
        print(f"{'-'*50} {'-'*12} {'-'*12} {'-'*20}")
        
        for config in configs:
            if config["successful_runs"] == 0:
                print(f"{config['name']:<50} {'FAILED':<12} {'-':<12} {'-':<20}")
                continue
            
            time_ratio = config["avg_duration_seconds"] / baseline["avg_duration_seconds"] if baseline["avg_duration_seconds"] > 0 else 0
            mem_ratio = config["avg_memory_mb"] / baseline["avg_memory_mb"] if baseline["avg_memory_mb"] > 0 else 0
            
            print(f"{config['name']:<50} "
                  f"{config['avg_duration_seconds']:<12.1f} "
                  f"{config['avg_memory_mb']:<12.1f} "
                  f"({time_ratio:.1f}x time, {mem_ratio:.1f}x mem)")


def get_default_configurations():
    """Get default build configurations to test."""
    return [
        # Baseline: Debug build
        {
            "name": "cargo test --no-run",
            "cmd": ["cargo", "test", "--no-run"],
            "env_vars": {}
        },
        # Debug with limited parallelism
        {
            "name": "cargo test --no-run -j 2",
            "cmd": ["cargo", "test", "--no-run", "-j", "2"],
            "env_vars": {}
        },
        # Release build
        {
            "name": "cargo test --release --no-run",
            "cmd": ["cargo", "test", "--release", "--no-run"],
            "env_vars": {}
        },
        # Release with limited parallelism
        {
            "name": "cargo test --release --no-run -j 2",
            "cmd": ["cargo", "test", "--release", "--no-run", "-j", "2"],
            "env_vars": {}
        },
        # Release with no LTO
        {
            "name": "cargo test --release --no-run (no LTO)",
            "cmd": ["cargo", "test", "--release", "--no-run"],
            "env_vars": {"CARGO_PROFILE_RELEASE_LTO": "false"}
        },
        # Release with fat LTO
        {
            "name": "cargo test --release --no-run (fat LTO)",
            "cmd": ["cargo", "test", "--release", "--no-run"],
            "env_vars": {"CARGO_PROFILE_RELEASE_LTO": "fat"}
        },
        # Release with lower optimization
        {
            "name": "cargo test --release --no-run (opt-level=2)",
            "cmd": ["cargo", "test", "--release", "--no-run"],
            "env_vars": {"CARGO_PROFILE_RELEASE_OPT_LEVEL": "2"}
        },
        # Single package builds
        {
            "name": "cargo test -p binius-field --release --no-run",
            "cmd": ["cargo", "test", "-p", "binius-field", "--release", "--no-run"],
            "env_vars": {}
        },
        {
            "name": "cargo test -p binius-field --release --no-run -j 1",
            "cmd": ["cargo", "test", "-p", "binius-field", "--release", "--no-run", "-j", "1"],
            "env_vars": {}
        },
        # All features
        {
            "name": "cargo test --all --all-features --release --no-run",
            "cmd": ["cargo", "test", "--all", "--all-features", "--release", "--no-run"],
            "env_vars": {}
        },
        {
            "name": "cargo test --all --all-features --release --no-run -j 1",
            "cmd": ["cargo", "test", "--all", "--all-features", "--release", "--no-run", "-j", "1"],
            "env_vars": {}
        },
    ]


class BuildAnalyzer:
    """Analyze build benchmark results."""
    
    def load_results(self, filename):
        """Load results from JSON file."""
        with open(filename, 'r') as f:
            return json.load(f)
    
    def print_machine_comparison(self, results_list):
        """Compare results across different machines."""
        print(f"\n{'='*80}")
        print("MACHINE COMPARISON")
        print(f"{'='*80}\n")
        
        for i, results in enumerate(results_list):
            info = results["machine_info"]
            print(f"Machine {i+1}:")
            print(f"  Hostname: {info['hostname']}")
            print(f"  Platform: {info['platform']}")
            print(f"  CPUs: {info['cpu_count']}")
            print(f"  Memory: {info['total_memory_gb']:.1f} GB")
            print(f"  Tested at: {info['timestamp']}")
            print()
    
    def print_configuration_analysis(self, results_list):
        """Analyze configurations across machines."""
        # Collect all configuration names
        all_configs = set()
        for results in results_list:
            for config in results["configurations"]:
                if config["successful_runs"] > 0:
                    all_configs.add(config["name"])
        
        all_configs = sorted(all_configs)
        
        print(f"\n{'='*80}")
        print("CONFIGURATION ANALYSIS")
        print(f"{'='*80}\n")
        
        for config_name in all_configs:
            print(f"\n{config_name}:")
            print(f"{'-'*len(config_name)}")
            
            data = []
            for results in results_list:
                machine = results["machine_info"]["hostname"]
                config = next((c for c in results["configurations"] if c["name"] == config_name), None)
                
                if config and config["successful_runs"] > 0:
                    data.append({
                        "machine": machine,
                        "time": config["avg_duration_seconds"],
                        "memory": config["avg_memory_mb"],
                        "max_memory": config["max_memory_mb"]
                    })
            
            if not data:
                print("  No successful runs")
                continue
            
            # Sort by time
            data.sort(key=lambda x: x["time"])
            
            print(f"  {'Machine':<30} {'Time (s)':<12} {'Avg Mem (MB)':<12} {'Max Mem (MB)':<12}")
            print(f"  {'-'*30} {'-'*12} {'-'*12} {'-'*12}")
            
            for d in data:
                print(f"  {d['machine']:<30} {d['time']:<12.1f} {d['memory']:<12.1f} {d['max_memory']:<12.1f}")
            
            # Show ratios if multiple machines
            if len(data) > 1:
                fastest = data[0]
                print(f"\n  Relative performance (vs {fastest['machine']}):")
                for d in data[1:]:
                    time_ratio = d['time'] / fastest['time']
                    mem_ratio = d['memory'] / fastest['memory']
                    print(f"    {d['machine']}: {time_ratio:.2f}x slower, {mem_ratio:.2f}x more memory")
    
    def print_optimization_impact(self, results):
        """Analyze the impact of different optimizations."""
        print(f"\n{'='*80}")
        print("OPTIMIZATION IMPACT ANALYSIS")
        print(f"{'='*80}\n")
        
        configs = {c["name"]: c for c in results["configurations"] if c["successful_runs"] > 0}
        
        # Compare debug vs release
        if "cargo test --no-run" in configs and "cargo test --release --no-run" in configs:
            debug = configs["cargo test --no-run"]
            release = configs["cargo test --release --no-run"]
            
            print("Debug vs Release:")
            print(f"  Time: {release['avg_duration_seconds'] / debug['avg_duration_seconds']:.1f}x slower")
            print(f"  Memory: {release['avg_memory_mb'] / debug['avg_memory_mb']:.1f}x more")
            print()
        
        # Impact of parallelism
        parallel_pairs = [
            ("cargo test --release --no-run", "cargo test --release --no-run -j 2"),
            ("cargo test --no-run", "cargo test --no-run -j 2"),
        ]
        
        for full, limited in parallel_pairs:
            if full in configs and limited in configs:
                f_conf = configs[full]
                l_conf = configs[limited]
                
                print(f"{full} vs {limited}:")
                print(f"  Time: {l_conf['avg_duration_seconds'] / f_conf['avg_duration_seconds']:.1f}x")
                print(f"  Memory: {l_conf['avg_memory_mb'] / f_conf['avg_memory_mb']:.1f}x")
                print()
        
        # Impact of LTO
        if "cargo test --release --no-run" in configs and "cargo test --release --no-run (no LTO)" in configs:
            with_lto = configs["cargo test --release --no-run"]
            no_lto = configs["cargo test --release --no-run (no LTO)"]
            
            print("LTO impact (Release build):")
            print(f"  Time without LTO: {no_lto['avg_duration_seconds'] / with_lto['avg_duration_seconds']:.1f}x")
            print(f"  Memory without LTO: {no_lto['avg_memory_mb'] / with_lto['avg_memory_mb']:.1f}x")
            print()
        
        # Single package vs all
        if "cargo test --release --no-run" in configs and "cargo test -p binius-field --release --no-run" in configs:
            all_pkg = configs["cargo test --release --no-run"]
            single = configs["cargo test -p binius-field --release --no-run"]
            
            print("Single package (binius-field) vs all packages:")
            print(f"  Time: {single['avg_duration_seconds'] / all_pkg['avg_duration_seconds']:.1f}x")
            print(f"  Memory: {single['avg_memory_mb'] / all_pkg['avg_memory_mb']:.1f}x")
    
    def generate_recommendations(self, results_list):
        """Generate recommendations based on the analysis."""
        print(f"\n{'='*80}")
        print("RECOMMENDATIONS FOR CI")
        print(f"{'='*80}\n")
        
        # Find the most constrained machine
        min_memory = min(r["machine_info"]["total_memory_gb"] for r in results_list)
        min_cpus = min(r["machine_info"]["cpu_count"] for r in results_list)
        
        print(f"Based on the most constrained machine ({min_memory:.1f} GB RAM, {min_cpus} CPUs):\n")
        
        # Check which configurations succeeded on all machines
        all_success = []
        for results in results_list:
            for config in results["configurations"]:
                if config["successful_runs"] > 0:
                    name = config["name"]
                    if all(any(c["name"] == name and c["successful_runs"] > 0 
                              for c in r["configurations"]) 
                          for r in results_list):
                        all_success.append(name)
        
        all_success = list(set(all_success))
        
        if all_success:
            print("Configurations that worked on ALL machines:")
            for config in sorted(all_success):
                print(f"  ✓ {config}")
        
        # Find configs that failed on some machines
        failures = []
        for results in results_list:
            machine = results["machine_info"]["hostname"]
            mem = results["machine_info"]["total_memory_gb"]
            for config in results["configurations"]:
                if config["successful_runs"] == 0:
                    failures.append((machine, mem, config["name"]))
        
        if failures:
            print("\nConfigurations that FAILED on some machines:")
            for machine, mem, config in failures:
                print(f"  ✗ {config} (failed on {machine} with {mem:.1f}GB)")
        
        # Specific recommendations
        print("\nRecommendations:")
        
        if min_memory < 16:
            print("  1. For machines with <16GB RAM:")
            print("     - Use -j 1 or -j 2 for release builds")
            print("     - Consider disabling LTO (CARGO_PROFILE_RELEASE_LTO=false)")
            print("     - Split large crates into separate build jobs")
        
        if "cargo test --all --all-features --release --no-run -j 1" in all_success:
            print("  2. For all-features builds:")
            print("     - Always use -j 1 to minimize memory usage")
        
        print("  3. General CI strategy:")
        print("     - Run clippy and tests separately")
        print("     - Consider using debug builds for unit tests")
        print("     - Use release builds only for benchmarks/integration tests")
        print("     - Set explicit timeouts to detect hangs early")
    
    def export_csv(self, results_list, output_file):
        """Export results to CSV for further analysis."""
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Header
            writer.writerow([
                "Machine", "Platform", "CPUs", "Memory_GB", "Configuration",
                "Success", "Runs", "Avg_Time_Seconds", "Avg_Memory_MB", "Max_Memory_MB"
            ])
            
            # Data
            for results in results_list:
                info = results["machine_info"]
                for config in results["configurations"]:
                    writer.writerow([
                        info["hostname"],
                        info["platform"],
                        info["cpu_count"],
                        f"{info['total_memory_gb']:.1f}",
                        config["name"],
                        config["successful_runs"] > 0,
                        config["successful_runs"],
                        f"{config['avg_duration_seconds']:.1f}" if config["successful_runs"] > 0 else "",
                        f"{config['avg_memory_mb']:.1f}" if config["successful_runs"] > 0 else "",
                        f"{config['max_memory_mb']:.1f}" if config["successful_runs"] > 0 else ""
                    ])
        
        print(f"\nResults exported to {output_file}")


def cmd_benchmark(args):
    """Run the benchmark subcommand."""
    # Get configurations
    all_configs = get_default_configurations()
    
    if args.list:
        print("Available configurations:")
        for config in all_configs:
            print(f"  - {config['name']}")
        return
    
    # Filter configurations if requested
    if args.config:
        configs = [c for c in all_configs if c["name"] in args.config]
        if not configs:
            print(f"Error: No matching configurations found for: {args.config}")
            print("Use --list to see available configurations")
            return
    else:
        configs = all_configs
    
    # Check if we're in a Rust project
    if not os.path.exists("Cargo.toml"):
        print("Error: No Cargo.toml found. Please run this script from the root of a Rust project.")
        return
    
    # Run benchmarks
    benchmarker = BuildBenchmarker(args.output)
    
    # Handle Ctrl+C gracefully
    def signal_handler(sig, frame):
        print("\n\nInterrupted! Saving partial results...")
        if benchmarker.current_process:
            benchmarker.current_process.kill()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    # Run benchmarks
    results = benchmarker.run_benchmarks(configs, args.runs)
    
    # Show comparison
    benchmarker.compare_results(results)
    
    print(f"\nDetailed results saved to: {args.output}")
    print("\nTo analyze results:")
    print(f"  {sys.argv[0]} analyze {args.output}")


def cmd_analyze(args):
    """Run the analyze subcommand."""
    analyzer = BuildAnalyzer()
    
    # Load all result files
    results_list = []
    for filename in args.files:
        try:
            results = analyzer.load_results(filename)
            results_list.append(results)
            print(f"Loaded results from {filename}")
        except Exception as e:
            print(f"Error loading {filename}: {e}")
            continue
    
    if not results_list:
        print("No valid result files loaded")
        return
    
    # Single file analysis
    if len(results_list) == 1:
        results = results_list[0]
        print(f"\nAnalyzing results from {results['machine_info']['hostname']}")
        analyzer.print_optimization_impact(results)
    else:
        # Multi-machine comparison
        analyzer.print_machine_comparison(results_list)
        analyzer.print_configuration_analysis(results_list)
    
    # Always show recommendations
    analyzer.generate_recommendations(results_list)
    
    # Export to CSV if requested
    if args.csv:
        analyzer.export_csv(results_list, args.csv)


def cmd_compare(args):
    """Run the compare subcommand."""
    analyzer = BuildAnalyzer()
    
    # Load all result files
    results_list = []
    for filename in args.files:
        try:
            results = analyzer.load_results(filename)
            results_list.append(results)
            print(f"Loaded results from {filename}")
        except Exception as e:
            print(f"Error loading {filename}: {e}")
            continue
    
    if len(results_list) < 2:
        print("Need at least 2 result files to compare")
        return
    
    # Multi-machine comparison
    analyzer.print_machine_comparison(results_list)
    analyzer.print_configuration_analysis(results_list)
    analyzer.generate_recommendations(results_list)
    
    # Export to CSV if requested
    if args.csv:
        analyzer.export_csv(results_list, args.csv)


def main():
    parser = argparse.ArgumentParser(
        description="Build Benchmark Tool - Benchmark and analyze Rust build configurations",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Benchmark command
    bench_parser = subparsers.add_parser('benchmark', help='Run build benchmarks')
    bench_parser.add_argument("-o", "--output", default="build_benchmark_results.json",
                            help="Output file for results (default: build_benchmark_results.json)")
    bench_parser.add_argument("-r", "--runs", type=int, default=1,
                            help="Number of runs per configuration (default: 1)")
    bench_parser.add_argument("--config", nargs="+",
                            help="Specific configurations to run (by name)")
    bench_parser.add_argument("--list", action="store_true",
                            help="List available configurations and exit")
    
    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze benchmark results')
    analyze_parser.add_argument("files", nargs="+", help="Result files to analyze")
    analyze_parser.add_argument("--csv", help="Export results to CSV file")
    
    # Compare command
    compare_parser = subparsers.add_parser('compare', help='Compare multiple result files')
    compare_parser.add_argument("files", nargs="+", help="Result files to compare")
    compare_parser.add_argument("--csv", help="Export results to CSV file")
    
    args = parser.parse_args()
    
    # Default to benchmark if no subcommand specified
    if args.command is None:
        args.command = 'benchmark'
        args.output = "build_benchmark_results.json"
        args.runs = 1
        args.config = None
        args.list = False
    
    # Dispatch to appropriate command
    if args.command == 'benchmark':
        cmd_benchmark(args)
    elif args.command == 'analyze':
        cmd_analyze(args)
    elif args.command == 'compare':
        cmd_compare(args)


if __name__ == "__main__":
    main()