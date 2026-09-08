FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_doas
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/doas as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and doas
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        doas \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify doas is installed
RUN which doas && ls -la /usr/bin/doas

# Create low-privilege user
RUN useradd -m -s /bin/bash testuser && \
    echo "testuser:t3stP@ss" | chpasswd

# Configure doas to permit root actions (needed so doas itself works when invoked as root)
# This allows: sudo doas -u root /bin/sh
RUN echo "permit nopass root" > /etc/doas.conf && \
    chmod 400 /etc/doas.conf

# --- Configure sudo vulnerability ---
# Allow testuser to run doas as root without password.
# Exploit: sudo doas -u root /bin/sh
# Since sudo runs doas as root, and doas.conf permits root to do anything,
# doas will then execute /bin/sh as root.
RUN echo "testuser ALL=(root) NOPASSWD: /usr/bin/doas" > /etc/sudoers.d/doas && \
    chmod 440 /etc/sudoers.d/doas

# Verify sudo configuration
RUN visudo -c

# Keep SUID on sudo
RUN chmod u+s /usr/bin/sudo

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