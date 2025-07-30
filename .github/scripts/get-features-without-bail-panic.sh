#!/bin/bash
# Get all features except bail_panic and output as comma-separated list

set -euo pipefail

# Get all unique features from all packages in the workspace
ALL_FEATURES=$(cargo metadata --format-version 1 --no-deps | \
  jq -r '.packages[].features | to_entries | .[].key' | \
  grep -v '^default$' | \
  grep -v '^bail_panic$' | \
  sort -u | \
  paste -sd "," -)

# Export for use in CI
echo "ALL_FEATURES_WO_BAIL_PANIC=$ALL_FEATURES"

# Also output just the list for direct use
echo "$ALL_FEATURES"
