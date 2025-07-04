#!/usr/bin/env python3
"""
Rust Code Coverage Tool

A Python-based coverage tool that provides clean, formatted output for cargo-llvm-cov.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import List, Dict, Optional, Tuple

try:
    from tabulate import tabulate
    HAS_TABULATE = True
except ImportError:
    HAS_TABULATE = False
    print("Installing tabulate for better table formatting...")
    subprocess.run([sys.executable, "-m", "pip", "install", "tabulate"], capture_output=True)
    try:
        from tabulate import tabulate
        HAS_TABULATE = True
    except:
        pass


class CoverageRunner:
    def __init__(self):
        self.workspace_root = self._get_workspace_root()
        self.workspace_name = os.path.basename(self.workspace_root)
        # ANSI color codes
        self.colors = {
            'green': '\033[92m',
            'yellow': '\033[38;5;220m',  # Bright gold instead of dull yellow
            'red': '\033[91m',
            'reset': '\033[0m',
            'bold': '\033[1m'
        }
        
    def _get_workspace_root(self) -> str:
        """Get the workspace root directory from cargo metadata."""
        try:
            result = subprocess.run(
                ["cargo", "metadata", "--no-deps", "--format-version", "1"],
                capture_output=True,
                text=True,
                check=True
            )
            metadata = json.loads(result.stdout)
            return metadata["workspace_root"]
        except:
            return os.getcwd()
    
    def _get_all_packages(self) -> List[str]:
        """Get all packages in the workspace."""
        try:
            result = subprocess.run(
                ["cargo", "metadata", "--no-deps", "--format-version", "1"],
                capture_output=True,
                text=True,
                check=True
            )
            metadata = json.loads(result.stdout)
            return [pkg["name"] for pkg in metadata["packages"]]
        except:
            return []
    
    def _check_cargo_llvm_cov(self):
        """Check if cargo-llvm-cov is installed."""
        try:
            subprocess.run(["cargo", "llvm-cov", "--version"], 
                         capture_output=True, check=True)
        except:
            print("ERROR: cargo-llvm-cov not found. Installing...")
            subprocess.run(["cargo", "install", "cargo-llvm-cov"], check=True)
    
    def _build_command(self, args) -> List[str]:
        """Build the cargo llvm-cov command."""
        cmd = ["cargo", "llvm-cov", "--all-features", "--ignore-run-fail"]
        
        if args.workspace:
            cmd.append("--workspace")
        
        for pkg in args.packages:
            cmd.extend(["-p", pkg])
        
        for exclude in args.exclude:
            cmd.extend(["--exclude", exclude])
        
        if args.lib:
            cmd.append("--lib")
        
        for test in args.test:
            cmd.extend(["--test", test])
        
        if not args.debug:
            cmd.append("--release")
        
        if args.no_cfg_coverage_nightly:
            cmd.append("--no-cfg-coverage-nightly")
        
        # Add output format
        if args.format == "html":
            cmd.append("--html")
        elif args.format == "json":
            cmd.extend(["--json", "--output-path", "coverage.json"])
        elif args.format == "lcov":
            cmd.extend(["--lcov", "--output-path", "lcov.info"])
        
        return cmd
    
    def _format_path(self, path: str) -> str:
        """Format file path to be relative to workspace."""
        # Remove everything up to and including the workspace name
        pattern = f".*{self.workspace_name}/"
        return re.sub(pattern, "", path)
    
    def _colorize_percentage(self, percentage: str) -> str:
        """Add color to percentage based on value."""
        try:
            # Remove % sign and convert to float
            value = float(percentage.rstrip('%'))
            if value >= 95:
                # Excellent coverage - green + bold
                return f"{self.colors['bold']}{self.colors['green']}{percentage}{self.colors['reset']}"
            elif value >= 80:
                # Good coverage - green
                return f"{self.colors['green']}{percentage}{self.colors['reset']}"
            elif value >= 50:
                # Moderate coverage - yellow
                return f"{self.colors['yellow']}{percentage}{self.colors['reset']}"
            else:
                # Poor coverage - red
                return f"{self.colors['red']}{percentage}{self.colors['reset']}"
        except:
            return percentage
    
    def _parse_coverage_line(self, line: str) -> Optional[Dict]:
        """Parse a coverage report line."""
        # Skip header and separator lines
        if line.startswith("Filename") or line.startswith("-") or not line.strip():
            return None
        
        # Skip .cargo and .rustup files
        if ".cargo/" in line or ".rustup/" in line:
            return None
        
        # Skip TOTAL line
        if line.strip().startswith("TOTAL"):
            return None
        
        # Parse the coverage data using more flexible approach
        # The format has many columns and spaces, so we need to be careful
        parts = line.split()
        if len(parts) < 13:
            return None
        
        try:
            # Extract filename (first part)
            filename = parts[0]
            
            # Find numeric columns - they follow a pattern
            # regions, missed_regions, cover%, functions, missed_functions, executed%, lines, missed_lines, cover%, branches, missed_branches, cover%
            return {
                "filename": self._format_path(filename),
                "regions": {
                    "total": int(parts[1]),
                    "missed": int(parts[2]),
                    "coverage": parts[3]
                },
                "functions": {
                    "total": int(parts[4]),
                    "missed": int(parts[5]),
                    "coverage": parts[6]
                },
                "lines": {
                    "total": int(parts[7]),
                    "missed": int(parts[8]),
                    "coverage": parts[9]
                }
            }
        except (ValueError, IndexError):
            return None
    
    def _filter_output(self, output: str, package_filter: Optional[List[str]] = None) -> Tuple[str, List[Dict]]:
        """Filter and format the coverage output."""
        lines = output.split('\n')
        formatted_lines = []
        coverage_data = []
        table_data = []
        in_table = False
        
        for line in lines:
            # Skip info messages
            if "info: cargo-llvm-cov currently setting cfg" in line:
                continue
            
            # Detect start of coverage table
            if line.startswith("Filename") and "Regions" in line:
                in_table = True
                continue
            
            if in_table:
                if line.startswith("-"):
                    continue
                
                if line.strip() == "" or "warning:" in line:
                    # End of table - format and output it
                    if table_data and HAS_TABULATE:
                        # Add header
                        formatted_lines.append("")
                        formatted_lines.append(self._format_coverage_table(table_data))
                        table_data = []
                    in_table = False
                    if line.strip() == "":
                        formatted_lines.append("")
                    else:
                        formatted_lines.append(line)  # Keep warning line
                    continue
                
                # Skip .cargo and .rustup lines
                if ".cargo/" in line or ".rustup/" in line:
                    continue
                
                # For TOTAL line, skip it since we'll show our own summary
                if line.strip().startswith("TOTAL"):
                    continue
                
                # Process coverage data lines
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 13:
                        # Parse the line
                        filename = parts[0]
                        
                        # Apply filters
                        if package_filter:
                            # When testing a specific package, files without crate prefix belong to that package
                            # e.g., "circuits/base64.rs" belongs to the package being tested
                            # while "field/src/lib.rs" is from another crate
                            if not any(filter_path in filename for filter_path in package_filter):
                                # Check if this is a local file (no crate prefix)
                                has_crate_prefix = any(prefix in filename for prefix in 
                                                     ['field/', 'frontend/', 'prover/', 'transcript/', 
                                                      'utils/', 'verifier/', 'maybe-rayon/'])
                                if has_crate_prefix:
                                    continue  # Skip files from other crates
                        
                        # Format the path
                        formatted_path = self._format_path(filename)
                        
                        # Extract coverage data
                        try:
                            row_data = {
                                'filename': formatted_path,
                                'lines': {
                                    'total': int(parts[7]),
                                    'missed': int(parts[8]),
                                    'percent': parts[9]
                                },
                                'functions': {
                                    'total': int(parts[4]),
                                    'missed': int(parts[5]),
                                    'percent': parts[6]
                                }
                            }
                            table_data.append(row_data)
                            coverage_data.append(row_data)
                        except:
                            pass
            else:
                # Keep all other output (test results, etc.)
                # Format test output for better readability
                if "test result:" in line:
                    formatted_lines.append(f"\n{line}")
                elif "warning:" in line:
                    formatted_lines.append(f"\nWARNING: {line}")
                elif line.strip().startswith("Running"):
                    formatted_lines.append(f"\n{line.strip()}")
                else:
                    formatted_lines.append(line)
        
        # Output any remaining table data
        if table_data and HAS_TABULATE:
            formatted_lines.append("")
            formatted_lines.append(self._format_coverage_table(table_data))
        
        return '\n'.join(formatted_lines), coverage_data
    
    def _format_coverage_table(self, table_data: List[Dict]) -> str:
        """Format coverage data as a nice table with colors."""
        if not table_data:
            return ""
        
        # Add section header
        output = ["\nFile Coverage Details"]
        output.append("-" * 70)
        
        headers = ['File', 'Lines', 'Coverage', 'Functions', 'Coverage']
        rows = []
        
        for item in table_data:
            # Calculate covered lines/functions
            lines_covered = item['lines']['total'] - item['lines']['missed']
            funcs_covered = item['functions']['total'] - item['functions']['missed']
            
            # Format filename with proper padding
            filename = item['filename']
            if len(filename) > 45:
                filename = "..." + filename[-42:]  # Truncate long paths
            
            row = [
                filename,
                f"{lines_covered:>3}/{item['lines']['total']:<3}",
                self._colorize_percentage(item['lines']['percent']),
                f"{funcs_covered:>2}/{item['functions']['total']:<2}",
                self._colorize_percentage(item['functions']['percent'])
            ]
            rows.append(row)
        
        table = tabulate(rows, headers=headers, tablefmt='simple', colalign=('left', 'center', 'center', 'center', 'center'))
        output.append(table)
        
        return '\n'.join(output)
    
    def _format_total_line(self, parts: List[str]) -> str:
        """Format the TOTAL line with colors."""
        if HAS_TABULATE:
            # Extract percentages
            try:
                line_pct = parts[9]
                func_pct = parts[6]
                
                total_str = f"\n{self.colors['bold']}TOTAL{self.colors['reset']}"
                line_str = f"Lines: {self._colorize_percentage(line_pct)}"
                func_str = f"Functions: {self._colorize_percentage(func_pct)}"
                
                return f"{total_str:<30} {line_str:<30} {func_str}"
            except:
                return " ".join(parts)
        else:
            return " ".join(parts)
    
    def _calculate_summary(self, coverage_data: List[Dict]) -> Dict[str, float]:
        """Calculate coverage summary from parsed data."""
        total_lines = sum(item["lines"]["total"] for item in coverage_data)
        covered_lines = sum(item["lines"]["total"] - item["lines"]["missed"] for item in coverage_data)
        
        total_functions = sum(item["functions"]["total"] for item in coverage_data)
        covered_functions = sum(item["functions"]["total"] - item["functions"]["missed"] for item in coverage_data)
        
        line_coverage = (covered_lines / total_lines * 100) if total_lines > 0 else 0
        function_coverage = (covered_functions / total_functions * 100) if total_functions > 0 else 0
        
        return {
            "line_coverage": line_coverage,
            "function_coverage": function_coverage,
            "total_lines": total_lines,
            "covered_lines": covered_lines,
            "total_functions": total_functions,
            "covered_functions": covered_functions
        }
    
    def run(self, args):
        """Run coverage analysis."""
        self._check_cargo_llvm_cov()
        
        print("\nRust Code Coverage Analysis")
        print("=" * 50)
        
        if args.each_package:
            self._run_each_package(args)
        else:
            self._run_normal(args)
    
    def _run_normal(self, args):
        """Run coverage in normal mode."""
        # Build package filter
        package_filter = []
        if args.packages:
            for pkg in args.packages:
                # Remove binius- prefix for crate path
                crate_name = pkg[7:] if pkg.startswith("binius-") else pkg
                # The paths in coverage output don't have 'crates/' prefix
                package_filter.append(f"{crate_name}/src/")
        
        # Clean previous coverage data
        clean_cmd = ["cargo", "llvm-cov", "clean"]
        if args.workspace:
            clean_cmd.append("--workspace")
        for pkg in args.packages:
            clean_cmd.extend(["-p", pkg])
        subprocess.run(clean_cmd, capture_output=True)
        
        if args.packages:
            pkg_names = ", ".join(args.packages)
            print(f"\nTarget package{'s' if len(args.packages) > 1 else ''}: {pkg_names}")
        print("\nRunning tests with coverage instrumentation...\n")
        
        # Run coverage
        cmd = self._build_command(args)
        env = os.environ.copy()
        env["CARGO_TERM_COLOR"] = "always"
        
        if args.format in ["html", "json", "lcov"]:
            # For file outputs, just run the command
            result = subprocess.run(cmd, env=env, capture_output=True, text=True)
            # Filter info message from stderr
            stderr = '\n'.join(line for line in result.stderr.split('\n') 
                             if "info: cargo-llvm-cov currently setting cfg" not in line)
            if stderr:
                print(stderr, file=sys.stderr)
            
            if args.format == "html":
                print("\nHTML coverage report generated")
                print("   Location: target/llvm-cov/html/")
                print("   View: target/llvm-cov/html/index.html")
                if args.open:
                    import platform
                    if platform.system() == "Darwin":
                        subprocess.run(["open", "target/llvm-cov/html/index.html"])
                    elif platform.system() == "Linux":
                        subprocess.run(["xdg-open", "target/llvm-cov/html/index.html"])
            elif args.format == "json":
                # Also generate summary
                subprocess.run(["cargo", "llvm-cov", "report", "--json", 
                              "--output-path", "coverage-summary.json"] + 
                              (["--release"] if not args.debug else []),
                              capture_output=True)
                print("\nJSON coverage reports generated")
                print("   Detailed: coverage.json")
                print("   Summary: coverage-summary.json")
            elif args.format == "lcov":
                print("\nLCOV report generated")
                print("   File: lcov.info")
                print("   Use with IDE coverage viewers or CI services")
        else:
            # Summary format - use temporary files for output
            with tempfile.NamedTemporaryFile(mode='w+', suffix='.txt', delete=False) as temp_out:
                temp_output_path = temp_out.name
            
            with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as temp_json:
                temp_json_path = temp_json.name
            
            try:
                # Run coverage and capture both stdout and stderr
                process = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                output, _ = process.communicate()
                
                # Save to temp file for processing
                with open(temp_output_path, 'w') as outfile:
                    outfile.write(output)
                
                # Read and process the output file
                with open(temp_output_path, 'r') as f:
                    full_output = f.read()
                
                # Debug: check if we have the full output
                if "Filename" in full_output and "Regions" in full_output:
                    lines_count = len(full_output.split('\n'))
                    # print(f"DEBUG: Found {lines_count} lines in output")
                
                # Filter and format output
                formatted_output, coverage_data = self._filter_output(full_output, package_filter)
                print(formatted_output)
                
                # Generate JSON report for accurate summary
                report_cmd = ["cargo", "llvm-cov", "report", "--json", 
                             "--output-path", temp_json_path]
                if not args.debug:
                    report_cmd.append("--release")
                if args.packages:
                    for pkg in args.packages:
                        report_cmd.extend(["-p", pkg])
                elif args.workspace:
                    report_cmd.append("--workspace")
                
                subprocess.run(report_cmd, capture_output=True)
                
                # Calculate summary
                try:
                    with open(temp_json_path, 'r') as f:
                        data = json.load(f)
                        
                    if package_filter and args.packages:
                        # Filter JSON data for specific packages
                        files = data['data'][0]['files']
                        # Also check with 'crates/' prefix since JSON might have different paths
                        extended_filter = package_filter + [f"crates/{pf}" for pf in package_filter]
                        filtered_files = [f for f in files 
                                        if any(filter_path in f['filename'] for filter_path in extended_filter)]
                        
                        if filtered_files:
                            total_lines = sum(f['summary']['lines']['count'] for f in filtered_files)
                            covered_lines = sum(f['summary']['lines']['covered'] for f in filtered_files)
                            total_functions = sum(f['summary']['functions']['count'] for f in filtered_files)
                            covered_functions = sum(f['summary']['functions']['covered'] for f in filtered_files)
                            
                            line_pct = (covered_lines / total_lines * 100) if total_lines > 0 else 0
                            function_pct = (covered_functions / total_functions * 100) if total_functions > 0 else 0
                        else:
                            line_pct = function_pct = 0
                    else:
                        # Use overall totals
                        totals = data['data'][0]['totals']
                        line_pct = totals['lines']['percent']
                        function_pct = totals['functions']['percent']
                    
                    print(f"\nCoverage Summary")
                    print("-" * 30)
                    print(f"   Line Coverage:     {self._colorize_percentage(f'{line_pct:.2f}%')}")
                    print(f"   Function Coverage: {self._colorize_percentage(f'{function_pct:.2f}%')}")
                except Exception as e:
                    print(f"\nWARNING: Could not generate coverage summary: {e}")
            
            finally:
                # Clean up temp files
                if os.path.exists(temp_output_path):
                    os.remove(temp_output_path)
                if os.path.exists(temp_json_path):
                    os.remove(temp_json_path)
        
        print("\nAnalysis complete\n")
    
    def _run_each_package(self, args):
        """Run coverage for each package separately."""
        packages = self._get_all_packages()
        print(f"Found packages: {', '.join(packages)}\n")
        
        for pkg in packages:
            print("=" * 70)
            print(f"Package: {pkg}")
            print("=" * 70)
            
            # Clean previous coverage data
            subprocess.run(["cargo", "llvm-cov", "clean", "-p", pkg], 
                         capture_output=True)
            
            # Build package-specific args
            pkg_args = argparse.Namespace(**vars(args))
            pkg_args.packages = [pkg]
            pkg_args.workspace = False
            pkg_args.each_package = False
            
            # Run coverage for this package
            self._run_normal(pkg_args)
            print()


def main():
    parser = argparse.ArgumentParser(
        description="Rust Code Coverage Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Package selection
    parser.add_argument('-p', '--package', dest='packages', action='append', 
                       default=[], help='Run coverage for specific package(s)')
    parser.add_argument('--exclude', dest='exclude', action='append',
                       default=[], help='Exclude specific package(s)')
    parser.add_argument('--each-package', action='store_true',
                       help='Run coverage for each package separately')
    parser.add_argument('--lib', action='store_true',
                       help='Run only library tests')
    parser.add_argument('--test', dest='test', action='append',
                       default=[], help='Run specific test binary')
    
    # Output format
    parser.add_argument('--format', choices=['summary', 'html', 'json', 'lcov'],
                       default='summary', help='Output format (default: summary)')
    parser.add_argument('--open', action='store_true',
                       help='Open HTML report in browser (use with --format html)')
    
    # Build options
    parser.add_argument('--debug', action='store_true',
                       help='Build and test in debug mode (default: release)')
    parser.add_argument('--no-cfg-coverage-nightly', action='store_true',
                       help='Disable cfg(coverage_nightly) flag')
    
    args = parser.parse_args()
    
    # Set workspace flag
    args.workspace = not args.packages and not args.each_package
    
    runner = CoverageRunner()
    runner.run(args)


if __name__ == "__main__":
    main()