# Agent Guidelines

Guidelines for automated agents and contributors working in this repository:

1. **Safety & Zero Side Effects**:
   - Never run or install arbitrary packages.
   - Do not make outbound network requests unless executing explicit live collector tests with mock or authorized endpoints.
   - No credentials or API keys may be placed in code, tests, or documentation.

2. **Verification Invariants**:
   - Always verify that `npm run check` and `npm test` exit with 0.
   - Maintain strict determinism in test fixtures and ZIP packet generation.
   - Any modifications to `src/evidence/runner.mjs` must maintain existing cryptographic guarantees and fail-closed behaviors.

3. **Repository Cleanliness**:
   - Never commit generated reports from `npm run demo` or temporary keys.
