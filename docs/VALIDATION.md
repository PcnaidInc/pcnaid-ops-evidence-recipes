# Validation Guide

This document describes the testing and validation regimen for `@pcnaid/ops-evidence-recipes`.

## Test Suites

The test suite consists of 91 tests organized across three test files:
1. `tests/evidence.test.mjs`: Validates recipe parsing, observation evaluation, check operators, live collector plans, packet building, and Ed25519 signature verification.
2. `tests/cli.test.mjs`: Tests command-line interface execution, options validation, key generation atomicity, and verification workflows.
3. `tests/core.test.mjs`: Tests foundational data routines, RFC 6901 pointers, RFC 4180 CSV parsing, ZIP serialization, and network address classification.

## Running Tests

```bash
# Run all tests
npm test

# Run syntax checks
npm run check

# Run sample demonstrations
npm run demo
```
