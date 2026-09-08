FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_env_unsanitized (CVE-2002-0043)
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo configured to allow testuser to run postfix
# commands as root, combined with env_keep that passes dangerous
# environment variables (MAIL_CONFIG, MAIL_DEBUG) through sudo,
# simulating the CVE-2002-0043 unclean environment behavior.
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, postfix, and basic utilities
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        postfix \
        coreutils \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify postfix and sudo are installed
RUN which postfix && which sudo && ls -la /usr/bin/sudo

# Create low-privilege user
RUN useradd -m -s /bin/bash testuser && \
    echo "testuser:t3stP@ss" | chpasswd

# --- Configure sudo vulnerability ---
# This simulates CVE-2002-0043: sudo does not sanitize environment variables.
# We configure sudo to:
# 1. Allow testuser to run several commands as root (including su, sh, postfix tools)
# 2. Preserve dangerous environment variables (MAIL_CONFIG, MAIL_DEBUG) via env_keep
# This allows the attacker to control postfix configuration via MAIL_CONFIG
# and trigger debugger_command execution via MAIL_DEBUG when postfix crashes/debugs.
#
# The actual exploit: user sets MAIL_CONFIG to a directory with a malicious main.cf
# containing a debugger_command that copies /bin/sh to /tmp/sh with SUID root.
# When sudo runs and postfix reads the tainted config, the debugger runs as root.
RUN echo 'Defaults env_keep += "MAIL_CONFIG MAIL_DEBUG"' > /etc/sudoers.d/mail_env && \
    echo 'testuser ALL=(root) NOPASSWD: /bin/su, /bin/sh, /usr/bin/su' >> /etc/sudoers.d/mail_env && \
    chmod 440 /etc/sudoers.d/mail_env

# Verify sudo configuration
RUN visudo -c

# Keep SUID on sudo
RUN chmod u+s /usr/bin/sudo

# Ensure postfix config directory exists for the exploit to copy from
RUN ls -la /etc/postfix/main.cf

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