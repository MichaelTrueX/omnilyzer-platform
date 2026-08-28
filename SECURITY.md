<!--
File: SECURITY.md
Purpose: Defines vulnerability reporting and baseline repository security policy.
Related:
- docs/architecture/security-model.md
- CONTRIBUTING.md
- docs/architecture/tenancy-model.md
-->

# Security Policy

## Reporting vulnerabilities

Do not report security vulnerabilities through public GitHub issues. A private reporting channel will be defined before public release. Until then, disclose findings only through a private channel explicitly provided by the repository owners; if none is available, do not publish exploit details and request a private channel from an authorized maintainer.

The supported-version policy will be added when production packages exist.

## Sensitive information

Secrets must never be committed. This includes passwords, tokens, private keys, production connection details, and generated credentials. If exposure is suspected, treat the credential as compromised, rotate or revoke it promptly, preserve appropriate audit evidence, and assess downstream exposure.

Do not copy production data into spike or test environments without an approved anonymization process. Logs, fixtures, screenshots, and test artifacts must follow the same rule.

## Severity principles

Workspace isolation defects, authorization bypasses, and secret leakage are critical security defects. Dependency vulnerabilities must be evaluated according to both severity and practical exploitability in the platform's context; a low-use dependency does not remove the need for assessment, and a score alone does not determine the response.

See [`docs/architecture/security-model.md`](docs/architecture/security-model.md) for architectural controls and [`docs/architecture/tenancy-model.md`](docs/architecture/tenancy-model.md) for the planned isolation model.
