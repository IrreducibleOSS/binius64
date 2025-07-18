#!/usr/bin/env python3
"""
Compare coverage between current branch and main branch.
Safely handles git operations to ensure no work is lost.
"""

import subprocess
import sys
import os
import tempfile
from pathlib import Path

# Import the coverage module
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from coverage import run_coverage


class GitSafetyError(Exception):
    """Raised when git operations might lose user data."""
    pass


class CoverageComparer:
    def __init__(self):
        self.original_branch = None
        self.baseline_file = None
        
    def run_command(self, cmd, check=True, capture_output=False):
        """Run a command and return result."""
        print(f"Running: {' '.join(cmd)}")
        return subprocess.run(cmd, check=check, capture_output=capture_output, text=True)
    
    def get_current_branch(self):
        """Get current git branch name."""
        result = self.run_command(['git', 'rev-parse', '--abbrev-ref', 'HEAD'], capture_output=True)
        return result.stdout.strip()
    
    def check_working_tree_clean(self):
        """Check if working tree is clean for safe branch switching."""
        # Check for uncommitted changes
        result = self.run_command(['git', 'status', '--porcelain'], capture_output=True)
        if result.stdout.strip():
            print("\nERROR: You have uncommitted changes:")
            print(result.stdout)
            print("\nPlease commit or stash your changes before running coverage comparison.")
            print("You can use:")
            print("  git stash          # to temporarily save changes")
            print("  git commit -am     # to commit changes")
            return False
        
        # Check for untracked files
        result = self.run_command(['git', 'ls-files', '--others', '--exclude-standard'], capture_output=True)
        untracked = result.stdout.strip()
        if untracked:
            print("\nERROR: You have untracked files:")
            for file in untracked.split('\n'):
                print(f"  ?? {file}")
            print("\nPlease add or remove untracked files before running coverage comparison.")
            print("You can use:")
            print("  git add <files>    # to stage files")
            print("  git clean -fd      # to remove untracked files (careful!)")
            print("  .gitignore         # to ignore files permanently")
            return False
            
        return True
    
    def checkout_branch(self, branch):
        """Safely checkout a branch."""
        print(f"\nSwitching to {branch} branch...")
        self.run_command(['git', 'checkout', branch])
    
    def cleanup(self):
        """Cleanup function to restore original state."""
        try:
            # Return to original branch if we switched
            if self.original_branch:
                current = self.get_current_branch()
                if current != self.original_branch:
                    print(f"\nReturning to {self.original_branch} branch...")
                    self.run_command(['git', 'checkout', self.original_branch], check=False)
            
            # Clean up temporary files
            if self.baseline_file and os.path.exists(self.baseline_file):
                os.remove(self.baseline_file)
                
        except Exception as e:
            print(f"WARNING: Error during cleanup: {e}")
    
    def run_coverage_comparison(self, packages=None, all_packages=False, exclude=None):
        """Main function to run coverage comparison."""
        try:
            # Record current state
            self.original_branch = self.get_current_branch()
            print(f"Current branch: {self.original_branch}")
            
            if self.original_branch == "main":
                print("ERROR: Already on main branch. Please run from a feature branch.")
                return 1
            
            # Check that working tree is clean
            if not self.check_working_tree_clean():
                return 1
            
            # Create temporary file for baseline
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                self.baseline_file = f.name
            
            # Switch to main branch
            self.checkout_branch('main')
            
            # Run coverage on main branch using the imported function
            print("\nRunning coverage on main branch...")
            try:
                exit_code = run_coverage(
                    packages=packages,
                    all_packages=all_packages,
                    exclude=exclude,
                    save_baseline=self.baseline_file
                )
                if exit_code != 0:
                    print("WARNING: Coverage failed on main branch")
                    # Continue anyway - comparison will show the differences
            except Exception as e:
                print(f"WARNING: Coverage failed on main branch: {e}")
                # Continue anyway
            
            # Switch back to original branch
            self.checkout_branch(self.original_branch)
            
            # Run coverage with comparison
            print(f"\nRunning coverage on {self.original_branch} branch with comparison...")
            try:
                exit_code = run_coverage(
                    packages=packages,
                    all_packages=all_packages,
                    exclude=exclude,
                    compare_baseline=self.baseline_file,
                    fail_on_regression=True
                )
                return exit_code
            except Exception as e:
                print(f"ERROR: Coverage comparison failed: {e}")
                return 1
            
        except KeyboardInterrupt:
            print("\n\nInterrupted! Cleaning up...")
            return 1
        except Exception as e:
            print(f"\nERROR: {e}")
            return 1
        finally:
            # Always cleanup
            self.cleanup()


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Compare coverage between current branch and main branch"
    )
    # Package selection - matching coverage.py
    parser.add_argument('-p', '--package', dest='packages', action='append',
                       default=[], help='Run coverage for specific package(s)')
    parser.add_argument('--all-packages', action='store_true',
                       help='Run coverage for all packages separately')
    parser.add_argument('--exclude', dest='exclude', action='append',
                       default=[], help='Exclude specific package(s) when using --all-packages')
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.packages and not args.all_packages:
        parser.print_help()
        sys.exit(1)
    
    if args.packages and args.all_packages:
        print("ERROR: Cannot specify both --package and --all-packages")
        sys.exit(1)
        
    if args.exclude and not args.all_packages:
        print("ERROR: --exclude can only be used with --all-packages")
        sys.exit(1)
    
    comparer = CoverageComparer()
    sys.exit(comparer.run_coverage_comparison(args.packages, args.all_packages, args.exclude))


if __name__ == '__main__':
    main()