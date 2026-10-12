# Pcnaid Evidence Recipes (`@pcnaid/ops-evidence-recipes`)

Declarative evidence collection, observation evaluation, and cryptographic evidence packaging tool.

## Overview

`pcnaid-evidence` evaluates structured service configuration responses against declarative, pinned JSON recipes. It generates portable, cryptographically authenticatable evidence packets containing:
- Evaluated observations and check outcomes
- Redacted fields preserving defense-in-depth confidentiality
- Cryptographic provenance manifests with SHA-256 file hashes
- Optional detached Ed25519 digital signatures

## Design Principles

1. **Declarative Recipes**: Observation rules and assertions are expressed as versioned JSON recipes. No arbitrary scripting or dynamic code evaluation is permitted.
2. **Explicit Singleton Scope**: Recipes evaluate a single, discrete resource response (`pagination: single`). Bulk enumeration and ambiguous pagination are explicitly out of scope.
3. **No Credential Storage**: Recipes only reference environment variable names for authentication (`tokenEnv`). Secrets, tokens, or credentials are never stored in recipes or outputs.
4. **Defense-in-Depth Redaction**: Sensitive attributes (keys, passwords, tokens, query parameters) are automatically sanitized and redacted before inclusion in reports. Redacted fields cannot pass comparison checks.
5. **Cryptographic Integrity & Authentication**: Evidence packets are archived in an uncompressed ZIP STORE format with a SHA-256 manifest. Detached Ed25519 signatures authenticate packets against independently supplied public keys.

## Installation and Requirements

- Node.js >= 22.16
- Zero external runtime dependencies

```bash
npm install
npm run check
npm test
```

## CLI Usage

### Evaluate Offline / Fixture Evidence

```bash
node bin/pcnaid-evidence.mjs evidence \
  --recipe recipes/cloudflare-zone-ssl.json \
  --input examples/evidence/cloudflare-zone-ssl.json \
  --origin fixture \
  --out reports/cloudflare
```

### Collect Live Evidence

```bash
node bin/pcnaid-evidence.mjs evidence \
  --recipe recipes/cloudflare-zone-ssl.json \
  --live \
  --param zone_id=0123456789abcdef0123456789abcdef \
  --out reports/cloudflare-live
```

### Sign an Evidence Packet

```bash
# Generate keypair
node bin/pcnaid-evidence.mjs keygen --out ./keys

# Generate signed packet
node bin/pcnaid-evidence.mjs evidence \
  --recipe recipes/cloudflare-zone-ssl.json \
  --input examples/evidence/cloudflare-zone-ssl.json \
  --signing-key ./keys/private.pem \
  --out reports/signed-evidence
```

### Verify an Evidence Packet

```bash
node bin/pcnaid-evidence.mjs verify \
  --packet reports/signed-evidence/packet.zip \
  --public-key ./keys/public.pem \
  --require-signature
```

## Verification Scripts

- `npm run check`: Runs syntax checks across all code and JSON files.
- `npm test`: Runs the test suite covering engine logic, CLI operations, and security invariants.
- `npm run demo`: Evaluates all sample recipes and produces sample packets.

## Limitations

- A recipe result is an observation, not an auditor opinion or compliance certification.
- SHA-256 hashes detect alterations relative to a manifest; they do not authenticate independent source truth.
- Ed25519 signatures attest to the possession of the signing key at creation time, not trusted third-party time.
- All live requests are read-only HTTPS GET queries. No write actions are executed.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE) for details.
