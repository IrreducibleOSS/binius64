#!/bin/bash
# Build FFI library and run integration tests

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Get script directory and project root
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$SCRIPT_DIR/../.."

# Clean and build FFI library (for testing only)
cd "$PROJECT_ROOT"
cargo clean -p binius-prover-client
cargo build --release --features ffi-impl -p binius-prover-client

# Setup library paths
if [[ "$OSTYPE" == "darwin"* ]]; then
    LIB_EXT="dylib"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    LIB_EXT="so"
else
    echo -e "${RED}Unsupported platform: $OSTYPE${NC}"
    exit 1
fi

LIB_PATH="$PROJECT_ROOT/target/release"
BUILT_LIB="$LIB_PATH/libbinius_prover_client.$LIB_EXT"
EXPECTED_LIB="$LIB_PATH/libbinius_prover.$LIB_EXT"

[ ! -f "$BUILT_LIB" ] && { echo -e "${RED}Library not found: $BUILT_LIB${NC}"; exit 1; }

# Create symlink if needed
[ ! -f "$EXPECTED_LIB" ] && ln -sf "$(basename "$BUILT_LIB")" "$EXPECTED_LIB"

# Run tests
export BINIUS_PROVER_LIB_PATH="$LIB_PATH"
cargo test -p binius-prover-client
