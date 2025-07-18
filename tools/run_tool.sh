#!/bin/bash

# Generic Python tool runner with automatic venv management
# Usage: ./run_tool.sh <tool_path> <requirements_file> [args...]

set -e

# Check if we have at least 2 arguments
if [ "$#" -lt 2 ]; then
    echo "Usage: $0 <tool_path> <requirements_file> [args...]"
    echo "Example: $0 ./repo_activity_collector.py ./requirements/base.txt --help"
    exit 1
fi

TOOL_PATH="$1"
REQUIREMENTS_FILE="$2"
shift 2  # Remove first two args, keep the rest for forwarding

# Get absolute paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOL_PATH="$(cd "$(dirname "$TOOL_PATH")" && pwd)/$(basename "$TOOL_PATH")"
REQUIREMENTS_FILE="$(cd "$(dirname "$REQUIREMENTS_FILE")" && pwd)/$(basename "$REQUIREMENTS_FILE")"

# Create a venv name based on the requirements file
VENV_NAME=".venv_$(basename "$REQUIREMENTS_FILE" .txt)"
VENV_PATH="$SCRIPT_DIR/$VENV_NAME"

# Check if venv exists
if [ ! -d "$VENV_PATH" ]; then
    echo "Creating virtual environment at $VENV_PATH..."
    python3 -m venv "$VENV_PATH"
fi

# Activate venv
source "$VENV_PATH/bin/activate"

# Check if requirements have changed (simple check based on modification time)
REQUIREMENTS_STAMP="$VENV_PATH/.requirements_stamp"
if [ ! -f "$REQUIREMENTS_STAMP" ] || [ "$REQUIREMENTS_FILE" -nt "$REQUIREMENTS_STAMP" ]; then
    echo "Installing/updating requirements from $REQUIREMENTS_FILE..."
    pip install --upgrade pip > /dev/null 2>&1
    pip install -r "$REQUIREMENTS_FILE"
    touch "$REQUIREMENTS_STAMP"
fi

# Run the tool with all remaining arguments
python3 "$TOOL_PATH" "$@"
