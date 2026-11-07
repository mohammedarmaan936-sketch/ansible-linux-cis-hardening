# Contributing to Ansible Linux CIS Hardening

Thank you for contributing to the `ansible-linux-cis-hardening` project! We welcome contributions that enhance CIS Benchmark coverage, improve idempotent automation, and strengthen fleet security posture.

---

## Development Workflow

### 1. Fork & Clone

```bash
git clone https://github.com/mohammedarmaan936-sketch/ansible-linux-cis-hardening.git
cd ansible-linux-cis-hardening
```

### 2. Local Testing & Quality Gates

Run the local quality checks using the `Makefile` before submitting a PR:

```bash
# Run static CIS Level 1 compliance scan
make audit

# Run playbook syntax validation
make syntax

# Run yamllint & ansible-lint quality checks
make lint

# Run containerized dry-run in Ubuntu 22.04 container
make docker-test
```

### 3. Adding New CIS Controls

When adding a new benchmark control:
1. Define configurable default variables in [`roles/cis_ubuntu_hardening/defaults/main.yml`](roles/cis_ubuntu_hardening/defaults/main.yml).
2. Implement idempotent remediation tasks under the appropriate file in [`roles/cis_ubuntu_hardening/tasks/`](roles/cis_ubuntu_hardening/tasks/).
3. Add a corresponding test assertion in [`scripts/cis_compliance_audit.py`](scripts/cis_compliance_audit.py).
4. Update the control matrix table in [`README.md`](README.md).

---

## Coding Standards

- **Idempotency**: Every task must be idempotent. Clean repeated runs should result in zero `changed` states.
- **Fail-Safe Service Reloads**: Never restart services directly in tasks; always notify handlers.
- **Scoping**: All role variables must follow the `cis_` naming convention.
- **Python**: Scanner code in `scripts/` must strictly use the Python 3 standard library with zero external dependencies.
