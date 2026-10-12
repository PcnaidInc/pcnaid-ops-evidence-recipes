# Security Policy

## Reporting Security Issues

If you discover a security vulnerability, please report it privately via GitHub Security Advisories or contact the maintainers directly. Do not open public issues for undisclosed security vulnerabilities.

## Security Architecture

- **Scope Control**: Recipes enforce strict URL patterns and parameter constraints to prevent SSRF and path traversal.
- **SSRF Prevention**: Live requests perform DNS pre-checks to ensure target hostnames resolve exclusively to public routable IP addresses.
- **Redaction Engine**: Sensitive fields and credential strings are stripped prior to packet generation. Redacted fields are withheld from comparisons.
- **Key Separation**: Private signing keys must remain outside repositories.
