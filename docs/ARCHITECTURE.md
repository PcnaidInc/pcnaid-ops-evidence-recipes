# Architecture & Guarantees

`pcnaid-evidence` is structured around a four-stage pipeline:

```
[Declarative Recipe] + [Raw Response / Live GET]
                  │
                  ▼
         [Field Extraction & Redaction]
                  │
                  ▼
         [Observation Evaluation]
                  │
                  ▼
       [Cryptographic Evidence Packet]
```

## Security & Architectural Invariants

1. **Declarative Engine**:
   - Checks are strictly limited to supported operators: `equals`, `one_of`, `exists`, `nonempty`, `greater_or_equal`, and `all_equals`.
   - No code evaluation, templating, or shell execution is permitted.

2. **Network & SSRF Guardrails**:
   - `collectEvidence` only performs HTTPS GET operations on port 443.
   - Hostnames must match a pinned allowlist.
   - DNS pre-resolution verifies that all resolved IP addresses are public, non-private, non-loopback, and non-metadata endpoints before connecting.

3. **Confidentiality & Redaction**:
   - Deep recursive sanitization scrubs known secrets and tokens.
   - Any comparison targeting a redacted value automatically yields an `unknown` status rather than passing or failing.

4. **Evidence Integrity**:
   - Packages are compiled into uncompressed ZIP STORE format with deterministic ordering.
   - A `manifest.json` file records cryptographic SHA-256 digests for all package contents.
   - Optional detached Ed25519 signatures authenticate the manifest without relying on in-band trust.
