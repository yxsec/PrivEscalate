FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on socat
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on /usr/bin/socat allows
#   privilege escalation. While CVE-2004-1484 is a format
#   string bug in socat <= 1.4.0.2, the modern exploitation
#   path with SUID socat is:
#   socat stdin exec:/bin/sh,pty,stderr,setsid,sigint,sane
#   which yields a root shell when socat is SUID.
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, socat, and supporting tools
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        socat \
        binutils \
        gcc \
        grep \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Create low-privilege user
RUN useradd -m -s /bin/bash testuser && \
    echo "testuser:t3stP@ss" | chpasswd

# Place the exploit source code in the user's home directory for reference
COPY --chmod=644 <<'EXPLOIT' /home/testuser/591.c
/* socat_exp.c - Socat Format String Vulnerability
   socat <= 1.4.0.2 local exploit (Proof of Concept)
   Original CVE-2004-1484 / OSVDB-11035
   Modern exploitation with SUID socat:
     socat stdin exec:/bin/sh,pty,stderr,setsid,sigint,sane
*/
EXPLOIT

# Inject vulnerability: set SUID bit on socat
# This simulates the scenario where socat is installed SUID root,
# which is the prerequisite for CVE-2004-1484 exploitation.
# The original advisory title says "Not SETUID" meaning the vuln
# exists even without SUID, but SUID is needed for privilege escalation.
RUN chmod u+s /usr/bin/socat

# Verify vulnerability is in place
RUN ls -la /usr/bin/socat | grep -q "rws" && echo "SUID bit confirmed on socat"

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