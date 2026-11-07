# Security Policy

## Supported Versions

This project actively maintains and tests security baselines for the following LTS platforms:

| Distribution | Version | Supported |
| :--- | :--- | :---: |
| Ubuntu Server | 24.04 LTS (*Noble Numbat*) | :white_check_mark: |
| Ubuntu Server | 22.04 LTS (*Jammy Jellyfish*) | :white_check_mark: |
| Ubuntu Server | 20.04 LTS (*Focal Fossa*) | :white_check_mark: |

---

## Reporting a Vulnerability

Security is paramount to this project. If you discover a security vulnerability or a regression in any of the CIS benchmark enforcements, please do not open a public issue. Instead, report it privately:

1. **Email**: Send detailed vulnerability reports to `mohammedarmaan936@gmail.com`.
2. **Subject**: Prefix your email with `[SECURITY-VULNERABILITY] ansible-linux-cis-hardening`.
3. **Include**:
   - Description of the security flaw or configuration bypass.
   - Affected CIS Benchmark Control ID.
   - Minimal reproduction playbook or command.
   - Proposed remediation (if available).

We will acknowledge receipt within 48 hours and coordinate a coordinated disclosure and patch release.

---

## Benchmark Alignment

Security controls in this repository conform to the official benchmark published by the **Center for Internet Security (CIS)**:
- *CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0*
- *CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0*

