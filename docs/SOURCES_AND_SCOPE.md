# Sources and Scope

## Supported Evidence Sources

1. **Cloudflare Zone Settings** (`cloudflare-zone-setting`):
   - Scope: Individual zone settings endpoints (`ssl`, `always_use_https`, `min_tls_version`).
   - Pinned Host: `api.cloudflare.com`.

2. **Azure Storage Account Configuration** (`azure-storage`):
   - Scope: Single storage account properties via Azure Resource Manager.
   - Pinned Host: `management.azure.com`.
   - Fixed API Version: `2023-05-01`.

3. **Custom Operator REST** (`custom-rest`):
   - Scope: Operator-defined singleton configuration endpoints.
   - Requires explicit `--allow-host` declaration.
   - Query strings forbidden to prevent token/secret leakage into metadata.

## Non-Goals

- Comprehensive security compliance certification or auditor opinions.
- Broad asset crawling or recursive account enumeration.
- Active configuration remediation or resource mutation.
