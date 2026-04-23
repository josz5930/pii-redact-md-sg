## Scope

**Only practical, full-chain exploits are in scope.**

We consider a vulnerability report to be in scope **only** if it demonstrates a complete, realistic attack chain that an attacker could use in practice to achieve meaningful impact (e.g., remote code execution, privilege escalation, data exfiltration, or account takeover under normal operating conditions) that crosses a trust boundary.

The following are **explicitly out of scope**:
- Theoretical or partial vulnerabilities
- Exploits that require unrealistic attacker capabilities, privileged access, or non-standard configurations
- Issues that only affect development or test environments
- Rate limiting, denial-of-service, or resource exhaustion issues (unless part of a larger exploit chain)

## Reporting Requirements

**All reports must contain both of the following**:

1. **A complete, one-click proof-of-concept (PoC) script**  
   The PoC must be a single, self-contained script (or one-liner/command) that an authorized reviewer can execute with minimal setup to reliably reproduce the vulnerability end-to-end.

2. **Proposed code changes to fix the issue**  
   Include a clear patch, diff, or code snippet showing exactly how the vulnerability should be remediated. Vague suggestions ("add input validation") are not sufficient.

Reports that do not include **both** a working one-click PoC **and** concrete fix code will be closed without further review.

## What We Do Not Provide

- **No bounties or payments of any kind** — There is no monetary reward, swag, or other compensation for vulnerability reports.
- **No guaranteed response timeline** — We review reports on a best-effort basis.
- **No public acknowledgement** — Reporters should expect that they will NOT be credited publicly or in any changelog, blog post, or security advisory.

## How to Report

Please report vulnerabilities **privately** using GitHub's [Private Vulnerability Reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-security-advisories) feature (enabled on this repository).

**Do not** open public issues or pull requests for security vulnerabilities.

Thank you for helping keep this project secure.
