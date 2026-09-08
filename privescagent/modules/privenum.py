"""PrivEnum: compact deterministic Linux privilege enumeration.

The primary path executes one auditable shell command containing common Linux
privilege-escalation checks. A five-command fallback is retained for targets
that cannot execute the compact script.
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# Compact enumeration script — covers all privesc vectors in a single command.
# It is optimized for LLM consumption with explicit section markers.
MINI_ENUM_SCRIPT = r'''#!/bin/sh
# Ensure /usr/sbin and /sbin are in PATH (getcap, setcap live there)
export PATH="$PATH:/usr/sbin:/sbin"
echo "=== ID ==="; id; groups
echo "=== SUDO ==="; sudo -l 2>/dev/null
echo "=== SUID ==="; find / -perm -4000 -type f 2>/dev/null
echo "=== SGID ==="; find / -perm -2000 -type f 2>/dev/null | head -20
echo "=== CAPS ==="; getcap -r / 2>/dev/null
echo "=== CRON ==="; cat /etc/crontab 2>/dev/null; ls -la /etc/cron* 2>/dev/null; crontab -l 2>/dev/null
echo "=== SYSTEMD_TIMERS ==="; systemctl list-timers --no-pager 2>/dev/null | head -20
echo "=== WRITABLE ==="; find / -writable -type f 2>/dev/null | grep -v '/proc\|/sys\|/dev' | head -30
echo "=== WRITABLE_DIRS ==="; for p in $(echo $PATH | tr ':' ' '); do [ -w "$p" ] && echo "WRITABLE_PATH: $p"; done 2>/dev/null
echo "=== PASSWD ==="; cat /etc/passwd
echo "=== SHADOW ==="; cat /etc/shadow 2>/dev/null | head -5
echo "=== SSH_KEYS ==="; ls -la /home/*/.ssh/ /root/.ssh/ 2>/dev/null; cat /home/*/.ssh/id_* /home/*/.ssh/authorized_keys 2>/dev/null | head -10
echo "=== DOCKER ==="; ls -la /var/run/docker.sock 2>/dev/null; docker ps 2>/dev/null | head -5
echo "=== DB_CREDS ==="; cat /home/*/.my.cnf /home/*/.pgpass /root/.my.cnf 2>/dev/null
echo "=== LD_PRELOAD ==="; cat /etc/ld.so.preload 2>/dev/null; echo "LD_PRELOAD=$LD_PRELOAD"; cat /etc/ld.so.conf 2>/dev/null
echo "=== HISTORY ==="; cat ~/.bash_history 2>/dev/null | tail -30
echo "=== ENV ==="; env 2>/dev/null | grep -E '^(PATH|LD_|HOME|USER|SHELL)'
echo "=== INTERESTING ==="; find / -name "*.conf" -writable 2>/dev/null | head -10; find / -name "*.bak" -o -name "*.old" -o -name "*.orig" 2>/dev/null | grep -v '/proc\|/sys' | head -10
'''

# Fallback: minimal enumeration commands if the compact script is unavailable.
FALLBACK_COMMANDS: List[Tuple[str, str, int]] = [
    ("whoami", "id && whoami", 5),
    ("sudo_privs", "sudo -l 2>/dev/null", 10),
    ("suid_binaries", "find / -perm -4000 -type f 2>/dev/null", 15),
    ("capabilities", "getcap -r / 2>/dev/null", 10),
    ("cron_jobs", "crontab -l 2>/dev/null; cat /etc/crontab 2>/dev/null; ls -la /etc/cron* 2>/dev/null", 10),
]

# Common distribution-provided SUID binaries that are normally non-actionable.
# Filtering this baseline noise is independent of any scenario identifier.
SAFE_SUID_BINARIES = {
    "/usr/bin/chfn", "/usr/bin/chsh", "/usr/bin/gpasswd",
    "/usr/bin/mount", "/usr/bin/newgrp", "/usr/bin/passwd",
    "/usr/bin/su", "/usr/bin/umount", "/usr/sbin/unix_chkpwd",
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
    "/usr/lib/openssh/ssh-keysign",
}

@dataclass
class EnumReport:
    """Structured enumeration report."""
    username: str = ""
    uid: int = -1
    groups: List[str] = field(default_factory=list)
    sudo_privs: str = ""
    sudo_nopasswd: List[str] = field(default_factory=list)
    suid_binaries: List[str] = field(default_factory=list)
    sgid_binaries: List[str] = field(default_factory=list)
    capabilities: Dict[str, str] = field(default_factory=dict)
    cron_jobs: str = ""
    writable_files: List[str] = field(default_factory=list)
    env_vars: Dict[str, str] = field(default_factory=dict)
    interesting_history: str = ""
    passwords_found: str = ""
    raw_outputs: Dict[str, str] = field(default_factory=dict)
    linpeas_used: bool = False

    def to_text(self) -> str:
        """Convert to text report for LLM consumption."""
        sections = []
        sections.append(f"=== User Info ===\nUser: {self.username} (uid={self.uid})\nGroups: {', '.join(self.groups)}")

        if self.sudo_privs:
            sections.append(f"=== Sudo Privileges ===\n{self.sudo_privs}")
            if self.sudo_nopasswd:
                sections.append(f"NOPASSWD entries: {', '.join(self.sudo_nopasswd)}")

        if self.suid_binaries:
            sections.append("=== SUID Binaries (non-standard) ===\n" + "\n".join(self.suid_binaries))

        if self.capabilities:
            cap_lines = [f"{path}: {cap}" for path, cap in self.capabilities.items()]
            sections.append("=== Capabilities ===\n" + "\n".join(cap_lines))

        if self.cron_jobs:
            sections.append(f"=== Cron Jobs ===\n{self.cron_jobs}")

        if self.writable_files:
            sections.append("=== Writable Files (interesting) ===\n" + "\n".join(self.writable_files[:20]))

        if self.passwords_found:
            sections.append(f"=== Passwords / Credentials ===\n{self.passwords_found}")

        if self.interesting_history:
            sections.append(f"=== Interesting History ===\n{self.interesting_history}")

        return "\n\n".join(sections)


class PrivEnum:
    """Privilege-escalation enumeration with compact and fallback modes."""

    def __init__(self, use_linpeas: bool = True):
        # Primary mode: mini enum script (1 step, all vectors)
        # Fallback: individual commands (5 steps)
        self._use_mini = True  # always prefer mini script
        self._phase = "mini" if self._use_mini else "fallback"
        self._current_idx = 0
        self._raw_outputs: Dict[str, str] = {}
        self._report: Optional[EnumReport] = None
        self._linpeas_raw: str = ""

    @property
    def is_complete(self) -> bool:
        if self._use_mini:
            return self._phase == "done"
        return self._current_idx >= len(FALLBACK_COMMANDS)

    @property
    def num_steps(self) -> int:
        """Estimated number of steps this module will consume."""
        return 1 if self._use_mini else len(FALLBACK_COMMANDS)

    @property
    def report(self) -> Optional[EnumReport]:
        if self._report is None and self.is_complete:
            if self._use_mini:
                self._report = self._parse_mini_enum(self._linpeas_raw)
            else:
                self._report = self._parse_fallback()
        return self._report

    def next_command(self) -> Optional[Tuple[str, str]]:
        """Return (name, command) for the next enumeration step."""
        if self.is_complete:
            return None

        if self._use_mini:
            if self._phase == "mini":
                # Send raw script directly (readable in logs)
                # Escape single quotes for sh -c wrapper
                script = MINI_ENUM_SCRIPT.strip()
                script_escaped = script.replace("'", "'\\''")
                cmd = f"sh -c '{script_escaped}' 2>/dev/null"
                return ("mini_enum", cmd)
        else:
            # Fallback mode
            name, cmd, _timeout = FALLBACK_COMMANDS[self._current_idx]
            return (name, cmd)

    def record_result(self, name: str, output: str):
        """Record the output of an enumeration command."""
        self._raw_outputs[name] = output

        if self._use_mini:
            if name == "mini_enum":
                self._linpeas_raw = output  # reuse linpeas parser
                self._phase = "done"
        else:
            self._current_idx += 1

        self._report = None  # invalidate cache

    # ------------------------------------------------------------------
    # Mini enum script output parsing
    # ------------------------------------------------------------------

    def _parse_mini_enum(self, raw: str) -> EnumReport:
        """Parse mini enum script output (=== SECTION === delimited)."""
        report = EnumReport(linpeas_used=False, raw_outputs=dict(self._raw_outputs))

        # Split by section markers
        sections = {}
        current_section = None
        current_lines = []
        for line in raw.splitlines():
            if line.strip().startswith("=== ") and line.strip().endswith(" ==="):
                if current_section:
                    sections[current_section] = "\n".join(current_lines)
                current_section = line.strip().strip("= ").strip()
                current_lines = []
            elif current_section:
                current_lines.append(line)
        if current_section:
            sections[current_section] = "\n".join(current_lines)

        # Parse ID
        self._parse_identity(report, sections.get("ID", ""))

        # Parse SUDO
        sudo_text = sections.get("SUDO", "")
        report.sudo_privs = sudo_text.strip()
        for line in sudo_text.splitlines():
            if "NOPASSWD" in line:
                parts = line.split(":")
                if len(parts) >= 2:
                    report.sudo_nopasswd.extend(
                        c.strip() for c in parts[-1].split(",")
                    )

        # Parse SUID
        for line in sections.get("SUID", "").splitlines():
            path = line.strip()
            if path and path.startswith("/") and path not in SAFE_SUID_BINARIES:
                report.suid_binaries.append(path)

        # Parse SGID
        for line in sections.get("SGID", "").splitlines():
            path = line.strip()
            if path and path.startswith("/"):
                report.sgid_binaries.append(path)

        # Parse CAPS
        for line in sections.get("CAPS", "").splitlines():
            match = re.match(r'(\S+)\s+(.*cap_\S+.*)', line.strip())
            if match:
                report.capabilities[match.group(1)] = match.group(2)

        # Parse CRON
        report.cron_jobs = sections.get("CRON", "").strip()

        # Parse WRITABLE
        for line in sections.get("WRITABLE", "").splitlines():
            path = line.strip()
            if path and path.startswith("/"):
                report.writable_files.append(path)

        # Parse HISTORY
        report.interesting_history = sections.get("HISTORY", "").strip()

        # Parse ENV
        for line in sections.get("ENV", "").splitlines():
            if "=" in line:
                k, _, v = line.partition("=")
                report.env_vars[k.strip()] = v.strip()

        # Parse PASSWD
        report.raw_outputs["passwd"] = sections.get("PASSWD", "")

        # Parse SHADOW readability
        shadow = sections.get("SHADOW", "").strip()
        if shadow and "Permission denied" not in shadow:
            report.raw_outputs["shadow"] = shadow

        # Parse SSH keys
        ssh_keys = sections.get("SSH_KEYS", "").strip()
        if ssh_keys:
            report.raw_outputs["ssh_keys"] = ssh_keys
            # Check for readable private keys
            if "BEGIN" in ssh_keys or "id_rsa" in ssh_keys:
                report.passwords_found += "\nSSH private key found"

        # Parse Docker access
        docker_info = sections.get("DOCKER", "").strip()
        if docker_info and "No such file" not in docker_info:
            report.raw_outputs["docker"] = docker_info
            if "docker.sock" in docker_info or "CONTAINER" in docker_info:
                report.raw_outputs["docker_accessible"] = "true"

        # Parse DB credentials
        db_creds = sections.get("DB_CREDS", "").strip()
        if db_creds and "No such file" not in db_creds:
            report.passwords_found += f"\nDB credentials: {db_creds[:200]}"

        # Parse LD_PRELOAD
        ld_info = sections.get("LD_PRELOAD", "").strip()
        if ld_info:
            report.raw_outputs["ld_preload"] = ld_info

        # Parse writable PATH directories
        writable_dirs = sections.get("WRITABLE_DIRS", "").strip()
        if writable_dirs:
            path_dirs = []
            for line in writable_dirs.splitlines():
                if "WRITABLE_PATH:" in line:
                    dir_path = line.replace("WRITABLE_PATH:", "").strip()
                    if dir_path:
                        path_dirs.append(dir_path)
            if path_dirs:
                report.raw_outputs["writable_path_dirs"] = path_dirs

        # Parse systemd timers
        timers = sections.get("SYSTEMD_TIMERS", "").strip()
        if timers:
            report.raw_outputs["systemd_timers"] = timers

        # Parse interesting files
        interesting = sections.get("INTERESTING", "").strip()
        if interesting:
            for line in interesting.splitlines():
                path = line.strip()
                if path and path.startswith("/"):
                    report.writable_files.append(path)

        return report

    # ------------------------------------------------------------------
    # Fallback parsing (same as before)
    # ------------------------------------------------------------------

    def _parse_fallback(self) -> EnumReport:
        """Parse fallback command outputs into EnumReport."""
        report = EnumReport(linpeas_used=False, raw_outputs=dict(self._raw_outputs))

        id_out = self._raw_outputs.get("whoami", "")
        self._parse_identity(report, id_out)

        sudo_out = self._raw_outputs.get("sudo_privs", "")
        report.sudo_privs = sudo_out.strip()
        for line in sudo_out.splitlines():
            if "NOPASSWD" in line:
                parts = line.split(":")
                if len(parts) >= 2:
                    report.sudo_nopasswd.extend(
                        c.strip() for c in parts[-1].split(",")
                    )

        suid_out = self._raw_outputs.get("suid_binaries", "")
        for line in suid_out.strip().splitlines():
            path = line.strip()
            if path and path.startswith("/") and path not in SAFE_SUID_BINARIES:
                report.suid_binaries.append(path)

        cap_out = self._raw_outputs.get("capabilities", "")
        for line in cap_out.strip().splitlines():
            match = re.match(r'(\S+)\s+(.*)', line.strip())
            if match and "cap_" in match.group(2):
                report.capabilities[match.group(1)] = match.group(2)

        report.cron_jobs = self._raw_outputs.get("cron_jobs", "").strip()

        return report

    @staticmethod
    def _parse_identity(report: EnumReport, output: str):
        """Parse id/whoami output."""
        for line in output.splitlines():
            line = line.strip()
            uid_match = re.search(r'uid=(\d+)\((\w+)\)', line)
            if uid_match:
                report.uid = int(uid_match.group(1))
                report.username = uid_match.group(2)
            groups_match = re.findall(r'groups?=.*?(\d+\(\w+\)(?:,\d+\(\w+\))*)', line)
            if groups_match:
                report.groups = re.findall(r'\((\w+)\)', groups_match[0])
