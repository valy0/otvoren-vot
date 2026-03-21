# Security Policy

## Statement

otvoren-vot is designed to support Bulgarian national elections. The integrity, confidentiality, and availability of this system directly affect democratic participation. We take security seriously and are committed to addressing vulnerabilities promptly and transparently.

We ask that security researchers follow responsible disclosure practices and give us the opportunity to investigate and remediate issues before public disclosure.

---

## Scope

The following categories of vulnerabilities are in scope:

- **Cryptographic vulnerabilities** — weaknesses in encryption, signing, zero-knowledge proofs, or random number generation used anywhere in the system.
- **Authentication bypass** — any mechanism that allows casting, modifying, or reading votes without proper authorization.
- **Data leakage** — exposure of voter identity, vote content, or personally identifiable information.
- **Bulletin board integrity** — tampering with or suppressing published election records, audit logs, or vote tallies.
- **Key management flaws** — improper generation, storage, transmission, or destruction of cryptographic keys.
- **Privilege escalation** — gaining administrative or elevated access beyond what is intended.

---

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

You may report through either of the following channels:

1. **Email:** [security@otvoren-vot.bg](mailto:security@otvoren-vot.bg)
   - Encrypt your report using our PGP key (published at `docs/security/pgp-key.asc`).
   - Include a clear description, steps to reproduce, and any proof-of-concept material.

2. **GitHub Security Advisories:** Open a private advisory at `Security > Advisories > New draft security advisory` in this repository. GitHub keeps these confidential until we choose to publish.

Please provide as much detail as possible: affected component, potential impact, reproduction steps, and any suggested mitigations.

---

## Response Timeline

| Milestone | Target |
|-----------|--------|
| Acknowledgement | Within 48 hours of receipt |
| Initial triage and severity assessment | Within 7 days |
| Fix for critical vulnerabilities | Within 30 days |
| Fix for high/medium vulnerabilities | Within 90 days |
| Coordinated public disclosure | After fix is released |

We will keep you informed of progress throughout the process. If a timeline cannot be met, we will explain why and provide an updated estimate.

---

## What to Expect

- We will acknowledge your report promptly and confirm we have received it.
- We will keep you updated on our investigation and remediation progress.
- We will credit you in the release notes and security advisory when the issue is disclosed publicly, unless you prefer to remain anonymous.
- We will not take legal action against researchers who report in good faith and follow this policy.
- We ask that you do not publicly disclose details of the vulnerability until we have released a fix and coordinated disclosure.

---

## Out of Scope

The following are not considered valid reports under this policy:

- **Social engineering** attacks targeting individual contributors, maintainers, or voters.
- **Denial-of-service testing** (volumetric or application-layer) without prior written permission.
- **Physical attacks** against hardware, polling stations, or infrastructure.
- Vulnerabilities in third-party services or dependencies not under our control (report those upstream).
- Issues requiring physical access to a voter's device or session.
- Theoretical vulnerabilities without a demonstrated impact or proof of concept.

---

## Acknowledgements

We are grateful to the security researchers who responsibly disclose vulnerabilities and help us build a more trustworthy system. Credited researchers will be listed in `docs/security/hall-of-thanks.md` unless anonymity is requested.
