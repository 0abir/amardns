# Security Policy

## Supported Versions

Only the latest active release on `main` receives security updates.

| Version | Supported          |
| :------ | :----------------- |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take the security of AmarDNS seriously. If you discover a security vulnerability, please report it responsibly:

### Preferred Method: Private Vulnerability Reporting
Please use GitHub's built-in **Private Vulnerability Reporting**:
1. Navigate to the repository's **Security** tab.
2. Click **Report a vulnerability** under "Private vulnerability reporting".
3. Provide a detailed summary, steps to reproduce, and any proof of concept.

This ensures the advisory is discussed and patched in private before public disclosure.

### Response Timeline
* **Initial Acknowledgement**: Within 24 hours.
* **Triage & Assessment**: Within 48 hours.
* **Fix & Release**: As soon as possible depending on severity (typically 1–3 business days).

## Automated Security Infrastructure
AmarDNS employs multi-layered automated security verification:
* **CodeQL SAST**: Continuous static code analysis on every push and pull request.
* **RustSec Audit**: Daily vulnerability scanning against the official RustSec advisory database.
* **Dependabot**: Automated supply-chain dependency updates.
* **Zero-Allocation Protocol Parsing**: Wire-format DNS parsing engineered without dynamic heap allocations to eliminate use-after-free and buffer overflow vectors.
