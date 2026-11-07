#!/usr/bin/env python3
"""
================================================================================
CIS Ubuntu Linux Benchmark Level 1 Server - Automated Compliance Scanner
================================================================================
Evaluates repository Ansible configurations, templates, and task definitions
against 15 CIS Level 1 Benchmark security controls. Also supports live system
evaluation on active Ubuntu instances via the '--live' flag.

Target OS: Ubuntu 22.04 / 24.04 LTS
Zero external dependencies (Python 3 standard library only).
Exits with code 0 on 100% compliance; exits with code 1 if any control fails.
"""

import sys
import os
import re
import argparse
import json
import subprocess
from pathlib import Path
from typing import Dict, List, Any

# Terminal color styling
USE_COLOR = sys.stdout.isatty() and (os.name != "nt" or "TERM" in os.environ or os.name == "nt")
GREEN = "\033[92m" if USE_COLOR else ""
RED = "\033[91m" if USE_COLOR else ""
YELLOW = "\033[93m" if USE_COLOR else ""
CYAN = "\033[96m" if USE_COLOR else ""
BOLD = "\033[1m" if USE_COLOR else ""
RESET = "\033[0m" if USE_COLOR else ""
CHECK_MARK = "[PASS]"
CROSS_MARK = "[FAIL]"

def find_repo_root() -> Path:
    """Locate the repository root directory containing ansible.cfg."""
    current = Path(__file__).resolve().parent
    for p in [current, current.parent, current.parent.parent]:
        if (p / "ansible.cfg").exists() or (p / "site.yml").exists():
            return p
    return Path.cwd()

def read_file_safe(path: Path) -> str:
    """Read a text file safely returning normalized string with unix line endings."""
    if not path.is_file():
        return ""
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
        return content.replace("\r\n", "\n")
    except Exception:
        return ""

def read_proc_sys(param_path: str) -> str:
    """Read a kernel parameter directly from /proc/sys or return empty string."""
    p = Path("/proc/sys") / param_path.replace(".", "/")
    if p.exists():
        try:
            return p.read_text().strip()
        except Exception:
            return ""
    return ""

def parse_yaml_value(content: str, key: str) -> Any:
    """Extract scalar value or list elements from YAML content."""
    lines = content.split("\n")
    for i, line in enumerate(lines):
        m = re.match(rf"^\s*{re.escape(key)}\s*:(.*)$", line)
        if m:
            rest = m.group(1).split("#")[0].strip()
            if not rest:
                items = []
                for j in range(i + 1, len(lines)):
                    subline = lines[j]
                    sub_match = re.match(r"^\s*-\s*([^#]+)", subline)
                    if sub_match:
                        item_val = sub_match.group(1).strip().strip("\"'")
                        items.append(item_val)
                    elif subline.strip() == "" or subline.strip().startswith("#"):
                        continue
                    else:
                        break
                return items

            if (rest.startswith('"') and rest.endswith('"')) or (rest.startswith("'") and rest.endswith("'")):
                rest = rest[1:-1]

            if rest.isdigit():
                return int(rest)
            if rest.lower() in ("true", "yes"):
                return True
            if rest.lower() in ("false", "no"):
                return "no"
            return rest

    return None

class CISComplianceAuditor:
    def __init__(self, repo_root: Path, live_mode: bool = False):
        self.repo_root = repo_root
        self.live_mode = live_mode
        self.role_dir = repo_root / "roles" / "cis_ubuntu_hardening"
        self.defaults_file = self.role_dir / "defaults" / "main.yml"
        self.sshd_template = self.role_dir / "templates" / "sshd_config.j2"
        self.tasks_ssh = self.role_dir / "tasks" / "ssh_hardening.yml"
        self.tasks_kernel = self.role_dir / "tasks" / "kernel_network.yml"
        self.tasks_fs = self.role_dir / "tasks" / "filesystem_access.yml"
        self.tasks_fw = self.role_dir / "tasks" / "firewall_fail2ban.yml"

        # Cache file contents for static audit
        self.defaults_raw = read_file_safe(self.defaults_file)
        self.sshd_raw = read_file_safe(self.sshd_template)
        self.ssh_tasks_raw = read_file_safe(self.tasks_ssh)
        self.kernel_tasks_raw = read_file_safe(self.tasks_kernel)
        self.fs_tasks_raw = read_file_safe(self.tasks_fs)
        self.fw_tasks_raw = read_file_safe(self.tasks_fw)

        # Live system inspection cache
        if self.live_mode:
            self.live_sshd_raw = read_file_safe(Path("/etc/ssh/sshd_config"))
            modprobe_files = list(Path("/etc/modprobe.d").glob("*.conf")) if Path("/etc/modprobe.d").exists() else []
            self.live_modprobe_raw = "\n".join([read_file_safe(f) for f in modprobe_files])

    def run_all_checks(self) -> List[Dict[str, Any]]:
        """Run all 15 CIS Level 1 Benchmark validation checks."""
        return [
            self._check_1_1_1_1_cramfs(),
            self._check_1_1_1_2_freevxfs(),
            self._check_1_1_1_3_jffs2(),
            self._check_1_1_1_4_hfs_hfsplus(),
            self._check_1_1_1_8_usb_storage(),
            self._check_1_5_1_aslr(),
            self._check_3_1_1_ip_forward(),
            self._check_3_1_2_send_redirects(),
            self._check_3_2_1_accept_redirects(),
            self._check_3_2_8_tcp_syncookies(),
            self._check_3_5_1_1_ufw_service(),
            self._check_3_5_1_3_ufw_default_deny(),
            self._check_5_2_4_ssh_root_login(),
            self._check_5_2_5_ssh_max_auth_tries(),
            self._check_5_2_11_ssh_password_auth(),
        ]

    # 1. CIS 1.1.1.1
    def _check_1_1_1_1_cramfs(self) -> Dict[str, Any]:
        cid = "CIS 1.1.1.1"
        desc = "Disable mounting of cramfs filesystems"
        if self.live_mode:
            passed = "install cramfs /bin/true" in self.live_modprobe_raw or "blacklist cramfs" in self.live_modprobe_raw
            actual = "disabled in modprobe" if passed else "not disabled"
        else:
            disabled_fs = parse_yaml_value(self.defaults_raw, "cis_disabled_filesystems") or []
            has_default = "cramfs" in disabled_fs
            has_task = "cis_disabled_filesystems" in self.fs_tasks_raw and "install {{ fs }} /bin/true" in self.fs_tasks_raw
            passed = has_default and has_task
            actual = "disabled (/bin/true)" if passed else "missing"

        return {
            "id": cid,
            "title": desc,
            "category": "Filesystem",
            "expected": "cramfs disabled in modprobe",
            "actual": actual,
            "passed": passed
        }

    # 2. CIS 1.1.1.2
    def _check_1_1_1_2_freevxfs(self) -> Dict[str, Any]:
        cid = "CIS 1.1.1.2"
        desc = "Disable mounting of freevxfs filesystems"
        if self.live_mode:
            passed = "install freevxfs /bin/true" in self.live_modprobe_raw or "blacklist freevxfs" in self.live_modprobe_raw
            actual = "disabled in modprobe" if passed else "not disabled"
        else:
            disabled_fs = parse_yaml_value(self.defaults_raw, "cis_disabled_filesystems") or []
            passed = "freevxfs" in disabled_fs
            actual = "disabled (/bin/true)" if passed else "missing"

        return {
            "id": cid,
            "title": desc,
            "category": "Filesystem",
            "expected": "freevxfs disabled",
            "actual": actual,
            "passed": passed
        }

    # 3. CIS 1.1.1.3
    def _check_1_1_1_3_jffs2(self) -> Dict[str, Any]:
        cid = "CIS 1.1.1.3"
        desc = "Disable mounting of jffs2 filesystems"
        if self.live_mode:
            passed = "install jffs2 /bin/true" in self.live_modprobe_raw or "blacklist jffs2" in self.live_modprobe_raw
            actual = "disabled in modprobe" if passed else "not disabled"
        else:
            disabled_fs = parse_yaml_value(self.defaults_raw, "cis_disabled_filesystems") or []
            passed = "jffs2" in disabled_fs
            actual = "disabled (/bin/true)" if passed else "missing"

        return {
            "id": cid,
            "title": desc,
            "category": "Filesystem",
            "expected": "jffs2 disabled",
            "actual": actual,
            "passed": passed
        }

    # 4. CIS 1.1.1.4
    def _check_1_1_1_4_hfs_hfsplus(self) -> Dict[str, Any]:
        cid = "CIS 1.1.1.4"
        desc = "Disable mounting of hfs/hfsplus filesystems"
        if self.live_mode:
            passed = "install hfs /bin/true" in self.live_modprobe_raw and "install hfsplus /bin/true" in self.live_modprobe_raw
            actual = "disabled in modprobe" if passed else "not disabled"
        else:
            disabled_fs = parse_yaml_value(self.defaults_raw, "cis_disabled_filesystems") or []
            passed = "hfs" in disabled_fs and "hfsplus" in disabled_fs
            actual = "disabled (/bin/true)" if passed else "missing"

        return {
            "id": cid,
            "title": desc,
            "category": "Filesystem",
            "expected": "hfs & hfsplus disabled",
            "actual": actual,
            "passed": passed
        }

    # 5. CIS 1.1.1.8
    def _check_1_1_1_8_usb_storage(self) -> Dict[str, Any]:
        cid = "CIS 1.1.1.8"
        desc = "Disable mounting of usb-storage drivers"
        if self.live_mode:
            passed = "install usb-storage /bin/true" in self.live_modprobe_raw or "blacklist usb-storage" in self.live_modprobe_raw
            actual = "disabled in modprobe" if passed else "not disabled"
        else:
            disabled_fs = parse_yaml_value(self.defaults_raw, "cis_disabled_filesystems") or []
            passed = "usb-storage" in disabled_fs
            actual = "disabled (/bin/true)" if passed else "missing"

        return {
            "id": cid,
            "title": desc,
            "category": "Filesystem",
            "expected": "usb-storage disabled",
            "actual": actual,
            "passed": passed
        }

    # 6. CIS 1.5.1
    def _check_1_5_1_aslr(self) -> Dict[str, Any]:
        cid = "CIS 1.5.1"
        desc = "Enable Address Space Layout Randomization (ASLR)"
        if self.live_mode:
            val = read_proc_sys("kernel.randomize_va_space")
            passed = (val == "2")
            actual = f"kernel.randomize_va_space = {val}" if val else "unknown"
        else:
            val = parse_yaml_value(self.defaults_raw, "cis_sysctl_kernel_randomize_va_space")
            conf_has = "kernel.randomize_va_space" in self.kernel_tasks_raw
            passed = (val == 2 or str(val) == "2") and conf_has
            actual = f"randomize_va_space = {val}"

        return {
            "id": cid,
            "title": desc,
            "category": "Kernel / ASLR",
            "expected": "kernel.randomize_va_space = 2",
            "actual": actual,
            "passed": passed
        }

    # 7. CIS 3.1.1
    def _check_3_1_1_ip_forward(self) -> Dict[str, Any]:
        cid = "CIS 3.1.1"
        desc = "Ensure IP forwarding is disabled"
        if self.live_mode:
            val = read_proc_sys("net.ipv4.ip_forward")
            passed = (val == "0")
            actual = f"net.ipv4.ip_forward = {val}" if val else "unknown"
        else:
            val = parse_yaml_value(self.defaults_raw, "cis_sysctl_net_ipv4_ip_forward")
            conf_has = "net.ipv4.ip_forward" in self.kernel_tasks_raw
            passed = (val == 0 or str(val) == "0") and conf_has
            actual = f"net.ipv4.ip_forward = {val}"

        return {
            "id": cid,
            "title": desc,
            "category": "Network Sysctl",
            "expected": "net.ipv4.ip_forward = 0",
            "actual": actual,
            "passed": passed
        }

    # 8. CIS 3.1.2
    def _check_3_1_2_send_redirects(self) -> Dict[str, Any]:
        cid = "CIS 3.1.2"
        desc = "Ensure packet redirect sending is disabled"
        if self.live_mode:
            val = read_proc_sys("net.ipv4.conf.all.send_redirects")
            passed = (val == "0")
            actual = f"send_redirects = {val}" if val else "unknown"
        else:
            val = parse_yaml_value(self.defaults_raw, "cis_sysctl_net_ipv4_conf_all_send_redirects")
            passed = (val == 0 or str(val) == "0") and "net.ipv4.conf.all.send_redirects" in self.kernel_tasks_raw
            actual = f"send_redirects = {val}"

        return {
            "id": cid,
            "title": desc,
            "category": "Network Sysctl",
            "expected": "send_redirects = 0",
            "actual": actual,
            "passed": passed
        }

    # 9. CIS 3.2.1
    def _check_3_2_1_accept_redirects(self) -> Dict[str, Any]:
        cid = "CIS 3.2.1"
        desc = "Ensure packet redirect acceptance is disabled"
        if self.live_mode:
            val = read_proc_sys("net.ipv4.conf.all.accept_redirects")
            passed = (val == "0")
            actual = f"accept_redirects = {val}" if val else "unknown"
        else:
            val = parse_yaml_value(self.defaults_raw, "cis_sysctl_net_ipv4_conf_all_accept_redirects")
            passed = (val == 0 or str(val) == "0") and "net.ipv4.conf.all.accept_redirects" in self.kernel_tasks_raw
            actual = f"accept_redirects = {val}"

        return {
            "id": cid,
            "title": desc,
            "category": "Network Sysctl",
            "expected": "accept_redirects = 0",
            "actual": actual,
            "passed": passed
        }

    # 10. CIS 3.2.8
    def _check_3_2_8_tcp_syncookies(self) -> Dict[str, Any]:
        cid = "CIS 3.2.8"
        desc = "Ensure TCP SYN Cookies is enabled"
        if self.live_mode:
            val = read_proc_sys("net.ipv4.tcp_syncookies")
            passed = (val == "1")
            actual = f"tcp_syncookies = {val}" if val else "unknown"
        else:
            val = parse_yaml_value(self.defaults_raw, "cis_sysctl_net_ipv4_tcp_syncookies")
            passed = (val == 1 or str(val) == "1") and "net.ipv4.tcp_syncookies" in self.kernel_tasks_raw
            actual = f"tcp_syncookies = {val}"

        return {
            "id": cid,
            "title": desc,
            "category": "Network Sysctl",
            "expected": "net.ipv4.tcp_syncookies = 1",
            "actual": actual,
            "passed": passed
        }

    # 11. CIS 3.5.1.1
    def _check_3_5_1_1_ufw_service(self) -> Dict[str, Any]:
        cid = "CIS 3.5.1.1"
        desc = "Ensure UFW firewall is installed and enabled"
        if self.live_mode:
            try:
                res = subprocess.run(["ufw", "status"], capture_output=True, text=True, check=False)
                passed = "Status: active" in res.stdout
                actual = "active" if passed else "inactive"
            except FileNotFoundError:
                passed = False
                actual = "ufw not installed"
        else:
            manage_ufw = parse_yaml_value(self.defaults_raw, "cis_ufw_manage")
            has_enable_cmd = "ufw --force enable" in self.fw_tasks_raw
            passed = (manage_ufw is True) and has_enable_cmd
            actual = "enabled (managed)" if passed else "disabled"

        return {
            "id": cid,
            "title": desc,
            "category": "Firewall (UFW)",
            "expected": "ufw enabled and managed",
            "actual": actual,
            "passed": passed
        }

    # 12. CIS 3.5.1.3
    def _check_3_5_1_3_ufw_default_deny(self) -> Dict[str, Any]:
        cid = "CIS 3.5.1.3"
        desc = "Ensure UFW default incoming policy is DENY"
        if self.live_mode:
            try:
                res = subprocess.run(["ufw", "status", "verbose"], capture_output=True, text=True, check=False)
                passed = "Default: deny (incoming)" in res.stdout
                actual = "deny incoming" if passed else "not deny incoming"
            except FileNotFoundError:
                passed = False
                actual = "ufw not installed"
        else:
            policy = parse_yaml_value(self.defaults_raw, "cis_ufw_default_incoming_policy")
            has_task = "cis_ufw_default_incoming_policy" in self.fw_tasks_raw or "deny incoming" in self.fw_tasks_raw
            passed = str(policy).strip().lower() == "deny" and has_task
            actual = f"incoming = {policy}"

        return {
            "id": cid,
            "title": desc,
            "category": "Firewall (UFW)",
            "expected": "incoming policy = deny",
            "actual": actual,
            "passed": passed
        }

    # 13. CIS 5.2.4
    def _check_5_2_4_ssh_root_login(self) -> Dict[str, Any]:
        cid = "CIS 5.2.4"
        desc = "Ensure SSH PermitRootLogin is disabled"
        if self.live_mode:
            m = re.search(r"^\s*PermitRootLogin\s+(\S+)", self.live_sshd_raw, re.MULTILINE)
            val = m.group(1) if m else "yes"
            passed = val.lower() in ("no", "prohibit-password")
            actual = f"PermitRootLogin {val}"
        else:
            val = parse_yaml_value(self.defaults_raw, "cis_ssh_permit_root_login")
            has_template = "PermitRootLogin" in self.sshd_raw and "{{ cis_ssh_permit_root_login }}" in self.sshd_raw
            is_disabled = str(val).strip().lower() in ("no", "prohibit-password", "false")
            passed = is_disabled and has_template
            actual = f"PermitRootLogin {val}"

        return {
            "id": cid,
            "title": desc,
            "category": "OpenSSH Daemon",
            "expected": "PermitRootLogin no",
            "actual": actual,
            "passed": passed
        }

    # 14. CIS 5.2.5
    def _check_5_2_5_ssh_max_auth_tries(self) -> Dict[str, Any]:
        cid = "CIS 5.2.5"
        desc = "Ensure SSH MaxAuthTries is set to 4 or less"
        if self.live_mode:
            m = re.search(r"^\s*MaxAuthTries\s+(\d+)", self.live_sshd_raw, re.MULTILINE)
            val = int(m.group(1)) if m else 6
            passed = val <= 4
            actual = f"MaxAuthTries {val}"
        else:
            val = parse_yaml_value(self.defaults_raw, "cis_ssh_max_auth_tries")
            try:
                val_int = int(val)
                passed = val_int <= 4 and ("MaxAuthTries" in self.sshd_raw)
            except Exception:
                passed = False
            actual = f"MaxAuthTries {val}"

        return {
            "id": cid,
            "title": desc,
            "category": "OpenSSH Daemon",
            "expected": "MaxAuthTries <= 4",
            "actual": actual,
            "passed": passed
        }

    # 15. CIS 5.2.11
    def _check_5_2_11_ssh_password_auth(self) -> Dict[str, Any]:
        cid = "CIS 5.2.11"
        desc = "Ensure SSH PasswordAuthentication is disabled"
        if self.live_mode:
            m = re.search(r"^\s*PasswordAuthentication\s+(\S+)", self.live_sshd_raw, re.MULTILINE)
            val = m.group(1) if m else "yes"
            passed = val.lower() == "no"
            actual = f"PasswordAuth {val}"
        else:
            val = parse_yaml_value(self.defaults_raw, "cis_ssh_password_authentication")
            has_template = "PasswordAuthentication" in self.sshd_raw and "{{ cis_ssh_password_authentication }}" in self.sshd_raw
            is_disabled = str(val).strip().lower() in ("no", "false")
            passed = is_disabled and has_template
            actual = f"PasswordAuth {val}"

        return {
            "id": cid,
            "title": desc,
            "category": "OpenSSH Daemon",
            "expected": "PasswordAuthentication no",
            "actual": actual,
            "passed": passed
        }


def print_table(results: List[Dict[str, Any]], score: float, live_mode: bool) -> None:
    """Render a terminal table with color-coded PASS/FAIL indicators."""
    total = len(results)
    passed_count = sum(1 for r in results if r["passed"])
    mode_label = "LIVE HOST SCAN" if live_mode else "STATIC CODE ANALYSIS (IaC)"

    print("\n" + "=" * 92)
    print(f"{BOLD}{CYAN} CIS BENCHMARK LEVEL 1 SERVER - AUTOMATED AUDIT & DRIFT SCANNER {RESET}")
    print(f" Mode: {BOLD}{mode_label}{RESET} | Standard: CIS Ubuntu Linux Benchmark Level 1 Server")
    print("=" * 92)

    col_id = 14
    col_cat = 18
    col_desc = 30
    col_actual = 21
    col_status = 8

    header = (
        f"{'CIS ID':<{col_id}} "
        f"{'Category':<{col_cat}} "
        f"{'Description':<{col_desc}} "
        f"{'Enforced Value':<{col_actual}} "
        f"{'Status':<{col_status}}"
    )
    print(f"{BOLD}{header}{RESET}")
    print("-" * 92)

    for r in results:
        status_str = f"{GREEN}{CHECK_MARK}{RESET}" if r["passed"] else f"{RED}{CROSS_MARK}{RESET}"
        title_truncated = (r["title"][:col_desc-3] + "...") if len(r["title"]) > col_desc else r["title"]
        actual_truncated = (r["actual"][:col_actual-3] + "...") if len(r["actual"]) > col_actual else r["actual"]

        line = (
            f"{BOLD}{r['id']:<{col_id}}{RESET} "
            f"{r['category']:<{col_cat}} "
            f"{title_truncated:<{col_desc}} "
            f"{actual_truncated:<{col_actual}} "
            f"{status_str}"
        )
        print(line)

    print("-" * 92)
    score_color = GREEN if score == 100.0 else RED
    print(f"\n{BOLD}Compliance Summary:{RESET}")
    print(f"  Audit Mode:               {mode_label}")
    print(f"  Total Evaluated Controls: {total}")
    print(f"  Passed Controls:          {passed_count}")
    print(f"  Failed Controls:          {total - passed_count}")
    print(f"  Compliance Score:         {score_color}{BOLD}{score:.1f}%{RESET}")

    if score == 100.0:
        print(f"\n{GREEN}{BOLD}[PASS] 100% CIS Level 1 Server Compliance verified. Zero drift detected.{RESET}\n")
    else:
        print(f"\n{RED}{BOLD}[FAIL] Security posture drift detected! Remediate non-compliant controls.{RESET}\n")


def main():
    parser = argparse.ArgumentParser(
        description="CIS Ubuntu Linux Benchmark Level 1 Compliance & Drift Scanner"
    )
    parser.add_argument(
        "--format",
        choices=["table", "json", "summary"],
        default="table",
        help="Output presentation format (default: table)"
    )
    parser.add_argument(
        "--live",
        action="store_true",
        default=False,
        help="Execute live audit against the local running Linux operating system"
    )
    parser.add_argument(
        "--repo-dir",
        type=str,
        default=None,
        help="Path to repository root (auto-detected by default)"
    )
    args = parser.parse_args()

    repo_root = Path(args.repo_dir).resolve() if args.repo_dir else find_repo_root()
    auditor = CISComplianceAuditor(repo_root, live_mode=args.live)
    results = auditor.run_all_checks()

    total = len(results)
    passed_count = sum(1 for r in results if r["passed"])
    score = (passed_count / total * 100.0) if total > 0 else 0.0

    if args.format == "json":
        output = {
            "benchmark": "CIS Ubuntu Linux Level 1 Server",
            "mode": "live" if args.live else "static",
            "version": "1.0.0",
            "score_percentage": score,
            "total_controls": total,
            "passed_controls": passed_count,
            "failed_controls": total - passed_count,
            "status": "COMPLIANT" if score == 100.0 else "NON_COMPLIANT",
            "controls": results
        }
        print(json.dumps(output, indent=2))
    elif args.format == "summary":
        status_msg = "COMPLIANT" if score == 100.0 else "NON_COMPLIANT"
        mode_str = "Live" if args.live else "Static"
        print(f"CIS Compliance ({mode_str}): {score:.1f}% ({passed_count}/{total}) [{status_msg}]")
    else:
        print_table(results, score, live_mode=args.live)

    # Exit code: 0 if 100% compliance, 1 otherwise
    if score == 100.0:
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
