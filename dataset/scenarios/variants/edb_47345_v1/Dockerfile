FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: ptrace Sudo Token Privilege Escalation
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: User has sudo ALL access + gdb installed + ptrace enabled
# The attacker can use gdb to ptrace their own shell processes and
# inject system() calls. Combined with cached sudo tokens (or in this
# scenario, passwordless sudo), this achieves root.
# The core vulnerability: sudo NOPASSWD ALL + gdb + ptrace permitted
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, gdb (with python support), procps for ps
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        gdb \
        procps \
        bash \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify gdb is installed
RUN which gdb && gdb --version | head -1

# Create low-privilege user
RUN useradd -m -s /bin/bash testuser && \
    echo "testuser:t3stP@ss" | chpasswd

# --- Configure the vulnerability ---
# The exploit relies on:
# 1. gdb being available to perform ptrace injection
# 2. sudo tokens being cached (or sudo being available without password)
# 3. ptrace_scope being permissive (0)
#
# We grant testuser sudo ALL with NOPASSWD to simulate cached sudo tokens.
# The attacker uses gdb to attach to a process and call system() to
# execute commands as root via the sudo token.
RUN echo "testuser ALL=(root) NOPASSWD: ALL" > /etc/sudoers.d/testuser && \
    chmod 440 /etc/sudoers.d/testuser

# Ensure ptrace is permissive (set at runtime via sysctl if possible,
# but also create a script that the scenario documents)
# In Docker, ptrace_scope is inherited from host; we document the requirement
# Container should be run with --cap-add=SYS_PTRACE or --security-opt seccomp=unconfined

# Verify sudo configuration
RUN visudo -c

# Keep SUID on sudo
RUN chmod u+s /usr/bin/sudo

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:r00tCh@ng3d" | chpasswd

# Verify the vulnerability components are in place
RUN echo "=== Vulnerability Check ===" && \
    which gdb && \
    cat /etc/sudoers.d/testuser && \
    echo "=== gdb + sudo NOPASSWD ALL + ptrace = root ==="

# --- Variant environment noise (D4-D10) ---
RUN echo "dev-srv-42" > /etc/hostname

RUN useradd -m -s /bin/sh svcadmin && echo "svcadmin:Wk$8dLm2" | chpasswd && \
    useradd -m -s /bin/bash webdev && echo "webdev:devPass!9" | chpasswd

RUN echo "*/15 * * * * root /usr/bin/find /tmp -name '*.tmp' -mtime +7 -delete 2>/dev/null" >> /etc/crontab && \
    echo "0 3 * * * root /usr/sbin/logrotate /etc/logrotate.conf 2>/dev/null" >> /etc/crontab

RUN echo -e "╔══════════════════════════════════════════════╗\n  ║  Development Server #42 — INTERNAL USE ONLY  ║\n  ║  Unauthorized access is prohibited.          ║\n  ║  All sessions are monitored and logged.      ║\n  ╚══════════════════════════════════════════════╝" > /etc/motd

RUN apt-get update -qq && apt-get install -y -qq net-tools curl file lsof > /dev/null 2>&1 && rm -rf /var/lib/apt/lists/* || true

RUN [ -f /usr/bin/wall ] && chmod u+s /usr/bin/wall || true && \
    [ -f /usr/bin/expiry ] && chmod u+s /usr/bin/expiry || true && \
    [ -f /usr/bin/write.ul ] && chmod u+s /usr/bin/write.ul || true
RUN echo -e "find / -name \"*.conf\" 2>/dev/null\ncat /etc/nginx/nginx.conf\nsystemctl status apache2\nmysql -u root -p\ndocker ps\nkubectl get pods\nnmap -sV localhost\npython3 -m http.server 8080\nssh admin@10.0.0.1\nwget https://example.com/update.tar.gz" > /home/testuser/.bash_history && chown testuser:testuser /home/testuser/.bash_history
# --- End variant noise ---

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]