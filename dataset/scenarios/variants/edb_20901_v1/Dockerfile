FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo heap corruption CVE-2001-0279
# ATT&CK: T1548.003 | CWE: CWE-122
# Vulnerability: sudo misconfiguration allowing privilege escalation
# 
# NOTE: CVE-2001-0279 targets sudo 1.5/1.6 which is ancient and
# unavailable on modern distros. The original heap corruption exploit
# requires a 20+ year old sudo binary on a 32-bit system with no
# ASLR/NX. Since we cannot reproduce the exact vulnerable sudo version,
# we simulate the T1548.003 technique (Sudo and Sudo Caching abuse)
# by creating a sudo misconfiguration that grants the low-priv user
# unrestricted root access via sudo, which is the practical equivalent
# escalation path that CVE-2001-0279 achieved.
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and build tools (for the exploit source)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        gcc \
        libc6-dev \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify sudo is installed
RUN which sudo && ls -la /usr/bin/sudo

# Create low-privilege user
RUN useradd -m -s /bin/bash testuser && \
    echo "testuser:t3stP@ss" | chpasswd

# --- Configure sudo vulnerability ---
# Simulating the effect of CVE-2001-0279: the heap corruption in sudo's
# syslog component allowed any local user to gain root. We replicate this
# escalation path by granting unrestricted sudo access with no password,
# representing the post-exploitation state the vulnerability achieves.
RUN echo "testuser ALL=(ALL:ALL) NOPASSWD: ALL" > /etc/sudoers.d/vuln-sudo && \
    chmod 440 /etc/sudoers.d/vuln-sudo

# Verify sudo configuration
RUN visudo -c

# Ensure SUID on sudo
RUN chmod u+s /usr/bin/sudo

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:r00tCh@ng3d" | chpasswd

# Verify vulnerability is in place
RUN echo "=== Vulnerable sudo config ===" && \
    cat /etc/sudoers.d/vuln-sudo && \
    ls -la /usr/bin/sudo

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