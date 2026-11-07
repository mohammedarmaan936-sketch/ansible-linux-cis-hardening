# ==============================================================================
# Ansible Linux CIS Hardening - Development & Automation Makefile
# ==============================================================================

.PHONY: all help audit audit-live audit-json syntax lint dry-run deploy test docker-test

PYTHON ?= python3
ANSIBLE_PLAYBOOK ?= ansible-playbook
INVENTORY ?= inventory/hosts.ini

all: test

help:
	@echo "======================================================================"
	@echo " Ansible Linux CIS Level 1 Hardening Automation Suite"
	@echo "======================================================================"
	@echo "  make audit        - Run static CIS Level 1 compliance & drift scanner"
	@echo "  make audit-live   - Run live compliance scan against local Linux OS"
	@echo "  make audit-json   - Export CIS compliance results to JSON"
	@echo "  make syntax       - Validate Ansible playbook syntax"
	@echo "  make lint         - Run yamllint and ansible-lint code quality checks"
	@echo "  make dry-run      - Run playbook against staging in check/diff mode"
	@echo "  make deploy       - Execute full hardening baseline against fleet"
	@echo "  make docker-test  - Run containerized dry-run in Ubuntu 22.04"
	@echo "======================================================================"

audit:
	$(PYTHON) scripts/cis_compliance_audit.py --format table

audit-live:
	$(PYTHON) scripts/cis_compliance_audit.py --live --format table

audit-json:
	$(PYTHON) scripts/cis_compliance_audit.py --format json > cis-compliance-report.json
	@echo "Wrote compliance report to cis-compliance-report.json"

syntax:
	$(ANSIBLE_PLAYBOOK) site.yml -i $(INVENTORY) --syntax-check

lint:
	yamllint -d relaxed .
	ansible-lint site.yml

dry-run:
	$(ANSIBLE_PLAYBOOK) site.yml -i $(INVENTORY) --limit staging --check --diff

deploy:
	$(ANSIBLE_PLAYBOOK) site.yml -i $(INVENTORY) --limit production

test: syntax-check-local audit

syntax-check-local:
	@echo "Running CIS compliance validation..."
	$(PYTHON) scripts/cis_compliance_audit.py --format summary

docker-test:
	docker run --rm -v $$(pwd):/ansible -w /ansible ubuntu:22.04 bash -c "\
		apt-get update -qq && \
		DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 python3-pip sudo && \
		pip3 install ansible-core --break-system-packages 2>/dev/null || pip3 install ansible-core && \
		ansible-playbook site.yml -i 'localhost,' -c local --check --diff && \
		python3 scripts/cis_compliance_audit.py"
