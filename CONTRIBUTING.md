# Contributing to Pcnaid Evidence Recipes

Thank you for contributing to `@pcnaid/ops-evidence-recipes`.

## Development Guidelines

1. **Security & Cryptography**: All crypto operations must use Node.js built-in primitives (`node:crypto`). Keys must never be hardcoded or checked into repositories.
2. **Deterministic Outputs**: Ensure output sorting (canonical JSON keys, deterministic ZIP entries).
3. **No External Dependencies**: Keep the tool self-contained and zero-dependency.
4. **Testing**: Run `npm test` and `npm run check` before submitting pull requests. All tests must pass cleanly.
