# Tools Directory

This directory contains utility scripts for the Monbijou project. All tools follow a consistent pattern with automatic virtual environment management.

## Tool Architecture

Each tool consists of:
- A Python script (e.g., `coverage.py`) - The main implementation
- A bash wrapper script (e.g., `coverage`) - Provides a simple interface
- A requirements file in `requirements/` - Python dependencies
- Automatic virtual environment management via `run_tool.sh`

## Available Tools

### build_benchmark

Benchmark different Rust build configurations to measure resource usage (time and memory).

```bash
# Run benchmarks with default configurations
./tools/build_benchmark

# List available configurations
./tools/build_benchmark benchmark --list

# Run specific configurations
./tools/build_benchmark benchmark --config "cargo test --release --no-run"

# Analyze results
./tools/build_benchmark analyze build_benchmark_results.json

# Compare results from multiple machines
./tools/build_benchmark compare machine1.json machine2.json
```

**Features:**
- Measures build time and peak memory usage
- Tests various configurations (debug, release, LTO, parallelism)
- Compares results across different machines
- Generates CI optimization recommendations

### coverage

Generate test coverage reports for the project.

```bash
# Generate coverage report
./tools/coverage

# With custom options
./tools/coverage --html --open
```

### coverage-compare

Compare coverage reports between different runs or branches.

```bash
# Compare coverage between runs
./tools/coverage-compare report1.json report2.json
```

## Adding New Tools

To add a new tool:

1. Create your Python script:
   ```python
   #!/usr/bin/env python3
   """Tool description."""
   
   import argparse
   
   def main():
       parser = argparse.ArgumentParser(description="Tool description")
       # ... implementation
   
   if __name__ == "__main__":
       main()
   ```

2. Create the bash wrapper:
   ```bash
   #!/bin/bash
   # Wrapper for tool_name.py with automatic venv management
   
   SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
   exec "$SCRIPT_DIR/run_tool.sh" "$SCRIPT_DIR/tool_name.py" "$SCRIPT_DIR/requirements/tool_name_reqs.txt" "$@"
   ```

3. Make the wrapper executable:
   ```bash
   chmod +x tools/tool_name
   ```

4. Create requirements file at `requirements/tool_name_reqs.txt` (use `no_reqs.txt` if no dependencies)

## Virtual Environment Management

The `run_tool.sh` script automatically:
- Creates a virtual environment for each requirements file
- Activates the appropriate environment
- Installs/updates dependencies when requirements change
- Runs the Python tool with all arguments

Virtual environments are stored as `.venv_<name>` in the tools directory and are gitignored.

## Best Practices

1. **Naming**: Use descriptive names without `.py` extension for wrappers
2. **Documentation**: Include docstrings and help text in your Python scripts
3. **Dependencies**: Keep requirements minimal and versioned
4. **Error Handling**: Provide clear error messages and exit codes
5. **Testing**: Test tools on different platforms before committing