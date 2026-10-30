# Security Policy

## Supported versions

NightBuoy is currently pre-release development software. No production-supported release exists. The development branch receives fixes; do not use it for sensitive discussions or interpret an available test environment as a security certification.

## Reporting a vulnerability

Use GitHub's private vulnerability-reporting channel:
https://github.com/MattJackson/nightbuoy/security/advisories/new

Do not put private forum content, recovery files, credentials, account mappings or unredacted logs in a public issue. Include the affected revision, expected/observed behavior and a minimal synthetic example. Reports may cover confidentiality, identity linkage, consensus/authorization errors, recovery, unsafe transport or availability.

## Current assurance and limits

[ARCHITECTURE.md](ARCHITECTURE.md) defines the threat model and release gates. [docs/AUDIT.md](docs/AUDIT.md) preserves the initial independent agent review and subsequent remediation evidence. Material open findings block production release. Dependency checks and automated tests are part of validation, not a substitute for a professional security review.

Authorized readers can retain old keys/plaintext; revocation protects future epochs. A malicious frontend can steal unlocked keys. Direct network connections expose routing information to peers; Tor/proxy configuration must be tested rather than assumed. Never expose consensus RPC or ABCI endpoints to the public internet.
