# Security Policy

## Supported versions

| Version | Security updates | End of support |
| --- | --- | --- |
| 1.x | Yes | December 31, 2031, or five years after the initial 1.0.0 release, whichever is later |
| Earlier than 1.0 | No | — |

## Reporting a vulnerability

Use GitHub's [private vulnerability reporting form](https://github.com/Carlos-PC05/lab-report-audit/security/advisories/new). Please keep vulnerability details out of public issues.

Include the affected version, a description of the issue, the impact you observed, and a suggested fix if available. Leave credentials and personal data out of the report.

## What to expect

- We aim to acknowledge reports within 3 business days.
- We aim to share an initial assessment within 10 business days.
- We aim to release a fix and publish a coordinated advisory within 90 days. We'll credit you if you want to be named.

## Safe harbour

We will not take legal action against researchers who act in good faith, avoid privacy violations and service disruption, and give us reasonable time to address the issue before disclosure.

## Verifying releases

From version 1.0.0, releases are intended to include a CycloneDX SBOM, SHA-256 checksums, and attestations signed with Sigstore. Download the release assets, then run:

```bash
sha256sum -c SHA256SUMS
gh attestation verify reportaudit-1.0.0.tar.gz --repo Carlos-PC05/lab-report-audit
```
