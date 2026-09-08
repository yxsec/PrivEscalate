FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on /bin/bash (CVE-2019-18276)
# ATT&CK: T1548.001 | CWE: CWE-273
# Vulnerability: SUID bit set on /bin/bash allows privilege
#   escalation via the saved UID not being dropped properly.
#   Attacker compiles a shared object calling setuid(0) and
#   loads it with: /bin/bash -p -c 'enable -f ./libpwn.so x'
# Note: Debian bookworm ships bash 5.2 which has the CVE patched,
#   but the SUID bit on bash still allows -p (privileged mode)
#   to retain effective UID, enabling root shell via bash -p.
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, gcc (for exploit compilation), and bash
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        bash \
        gcc \
        libc6-dev \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Create low-privilege user
RUN useradd -m -s /bin/bash testuser && \
    echo "testuser:t3stP@ss" | chpasswd

# Inject vulnerability: set SUID bit on /bin/bash
# With SUID root on bash, running "bash -p" preserves effective UID 0
RUN chmod u+s /bin/bash

# Verify vulnerability is in place
RUN ls -la /bin/bash | grep -q "rws" && echo "SUID bit confirmed on /bin/bash"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:r00tCh@ng3d" | chpasswd

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