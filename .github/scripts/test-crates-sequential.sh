#!/bin/bash
# Test all crates sequentially with memory-conscious settings

set -euo pipefail

# Configuration
MAX_PARALLEL_JOBS="${MAX_PARALLEL_JOBS:-1}"
PROFILE="${PROFILE:-release}"
EXCLUDE_CRATES="${EXCLUDE_CRATES:-}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Get all crate names
echo "Discovering workspace crates..."
CRATES=$(cargo metadata --format-version 1 --no-deps | jq -r '.packages[].name' | sort)

# Count total crates
TOTAL_CRATES=$(echo "$CRATES" | wc -l | tr -d ' ')
CURRENT=0
FAILED_CRATES=""
SKIPPED_CRATES=""

echo "Found $TOTAL_CRATES crates in workspace"
echo

# Function to check if crate should be excluded
should_exclude() {
    local crate=$1
    if [ -z "$EXCLUDE_CRATES" ]; then
        return 1
    fi
    
    for excluded in $EXCLUDE_CRATES; do
        if [ "$crate" = "$excluded" ]; then
            return 0
        fi
    done
    return 1
}

# Function to get crate size estimate
get_crate_info() {
    local crate=$1
    local src_size=$(find . -name "*.rs" -path "*/target/*" -prune -o -type f -print | xargs grep -l "name = \"$crate\"" | xargs du -ch 2>/dev/null | tail -1 | cut -f1)
    echo "$src_size"
}

# Test each crate
for crate in $CRATES; do
    CURRENT=$((CURRENT + 1))
    
    # Check if should skip
    if should_exclude "$crate"; then
        echo -e "${YELLOW}[$CURRENT/$TOTAL_CRATES] Skipping $crate (excluded)${NC}"
        SKIPPED_CRATES="$SKIPPED_CRATES $crate"
        continue
    fi
    
    echo "::group::[$CURRENT/$TOTAL_CRATES] Testing $crate"
    echo -e "${GREEN}Building and testing $crate...${NC}"
    
    # Show some info about the crate
    echo "Crate info:"
    cargo metadata --format-version 1 --no-deps | jq -r ".packages[] | select(.name == \"$crate\") | \"  Version: \\(.version)\n  Path: \\(.manifest_path)\""
    
    # Clean to free memory from previous crate
    if [ "$CURRENT" -gt 1 ]; then
        echo "Cleaning previous build artifacts..."
        cargo clean -p "$previous_crate" 2>/dev/null || true
    fi
    
    # Build the crate
    echo
    echo "Building $crate..."
    if ! cargo build -p "$crate" --profile "$PROFILE" -j "$MAX_PARALLEL_JOBS"; then
        FAILED_CRATES="$FAILED_CRATES $crate"
        echo -e "${RED}Failed to build $crate${NC}"
        echo "::error::Failed to build $crate"
        echo "::endgroup::"
        continue
    fi
    
    # Test the crate
    echo
    echo "Testing $crate..."
    if ! cargo test -p "$crate" --profile "$PROFILE" -j "$MAX_PARALLEL_JOBS" -- --test-threads=2; then
        FAILED_CRATES="$FAILED_CRATES $crate"
        echo -e "${RED}Failed to test $crate${NC}"
        echo "::error::Failed to test $crate"
    else
        echo -e "${GREEN}Successfully tested $crate${NC}"
    fi
    
    echo "::endgroup::"
    
    # Remember for cleanup
    previous_crate="$crate"
    
    # Optional: Show memory usage
    if command -v free &> /dev/null; then
        echo "Memory status:"
        free -h
    fi
    echo
done

# Summary
echo
echo "========================================="
echo "Test Summary"
echo "========================================="
echo "Total crates: $TOTAL_CRATES"
echo "Tested: $((TOTAL_CRATES - $(echo "$SKIPPED_CRATES" | wc -w)))"

if [ -n "$SKIPPED_CRATES" ]; then
    echo -e "${YELLOW}Skipped:${NC}$SKIPPED_CRATES"
fi

if [ -n "$FAILED_CRATES" ]; then
    echo -e "${RED}Failed:${NC}$FAILED_CRATES"
    echo
    echo "::error::Test failed for crates:$FAILED_CRATES"
    exit 1
else
    echo -e "${GREEN}All tests passed!${NC}"
fi