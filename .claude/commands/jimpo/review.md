---
allowed-tools: Bash(gt info:*)
description: Code review a Graphite diff
---

## Read the diff

- Current Graphite diff information: `gt info --diff`

## Your task

Review the code diff as if you are the lead developer of the project. When performing code reviews, follow this systematic approach:

### 1. Initial Analysis
- Read through the entire diff to understand the overall change
- Identify the main purpose and scope of the changes
- Note which crates/modules are affected

### 2. Detailed Review Process
- Review changes file by file, in logical order
- For each significant change, consider:
  - Simple API Design: Are public interfaces clear, simple, and documented?
  - Tests: Are the changes adequately tested?
  - Correctness: Does the code do what it intends to do?
  - Safety: Do uses of unsafe Rust come with a comment explaining safety?
  - Style: Does it follow project conventions as documented in CONTRIBUTING.md?

### 3. Provide Feedback
- Start with a brief summary of what the changes accomplish
- Group feedback by severity:
  - **Critical**: Must be fixed (bugs, security issues, correctness problems)
  - **Important**: Should be addressed (performance issues, missing tests)
  - **Minor**: Consider changing (style, naming, documentation)
- Include specific line references and suggestions

## Code Review Checklist

### General Code Quality
- [ ] **Testing**: New functionality has tests, edge cases covered
- [ ] **Documentation**: Public APIs documented, complex logic explained
- [ ] **Code Style**: Follows Rust idioms and project conventions
- [ ] **Naming**: Clear, descriptive names following project conventions
- [ ] **Error Handling**: Proper error handling (no `unwrap()` in library code, `expect()` OK with clear rationale)
- [ ] **Performance**: Efficient algorithms, appropriate use of `binius_utils::rayon` for parallelism
- [ ] **Clean Code**: No commented-out code (e.g., debug println statements), no dead code

### Binius64-Specific Checks

#### Code Organization
- [ ] **Prover/verifier separation**: Cryptographic protocols split code into binius-verifier and binius-prover crates

#### Field Arithmetic
- [ ] **Packed Field Operations**: Efficient use of packed field types in prover code

### Code Patterns
- [ ] **Trait Implementations**: Complete and consistent trait implementations
- [ ] **Module Organization**: Clear separation of concerns, proper visibility

### Testing Patterns
- [ ] **Pseudo-Random Testing**: Uses `StdRng::seed_from_u64(0)` for reproducible tests
- [ ] **Property-Based Tests**: Tests mathematical properties using the proptest crate
- [ ] **Use Test Utilities**: Uses helper functions from `binius_math::test_utils` module where appropriate
