# ZKL Snapshots

This directory contains snapshot files for the ZKL circuit statistics. These snapshots are used to ensure that circuit changes are intentional and tracked.

## Usage

- **Check snapshot**: `cargo run -p zkl -- check-snapshot`
- **Update snapshot**: `cargo run -p zkl -- bless-snapshot`

NOTE: run those in the root directory of the project.

## CI Integration

The GitHub Actions CI workflow automatically checks that the circuit statistics match the snapshot on every pull request. If the statistics change, the CI will fail and you'll need to update the snapshot using the bless command above.

## Snapshot File

- `stat_output.snap`: Contains the expected output of the `zkl stat` command including circuit configuration and statistics (number of gates, constraints, etc.)
