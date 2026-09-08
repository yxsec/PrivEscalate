FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_arch-nspawn
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/arch-nspawn as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and required packages
# arch-nspawn doesn't exist as a Debian package - it's an Arch Linux tool.
# We'll create a script that mimics arch-nspawn's behavior (spawning a shell
# in a namespace context) since the real tool is Arch-specific.
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        systemd-container \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Create a simulated arch-nspawn binary that behaves like the real one.
# The real arch-nspawn from Arch Linux is a bash script that uses systemd-nspawn
# to spawn into a container/chroot. It accepts a root directory and then
# arbitrary commands to run. This allows command execution as root when
# run via sudo.
RUN printf '#!/bin/bash\n\
# arch-nspawn - simplified version mimicking Arch Linux devtools arch-nspawn\n\
# Usage: arch-nspawn <root-dir> [command...]\n\
if [ $# -lt 1 ]; then\n\
    echo "Usage: arch-nspawn <root-dir> [command...]" >&2\n\
    exit 1\n\
fi\n\
CHROOT="$1"\n\
shift\n\
if [ $# -eq 0 ]; then\n\
    exec /bin/bash\n\
else\n\
    exec "$@"\n\
fi\n' > /usr/bin/arch-nspawn && \
    chmod 755 /usr/bin/arch-nspawn

# Verify arch-nspawn is installed
RUN which arch-nspawn && ls -la /usr/bin/arch-nspawn

# Create low-privilege user
RUN useradd -m -s /bin/bash testuser && \
    echo "testuser:t3stP@ss" | chpasswd

# --- Configure sudo vulnerability ---
# arch-nspawn can execute arbitrary commands when given a root directory
# With sudo: sudo arch-nspawn /tmp /bin/sh -> root shell
RUN echo "testuser ALL=(root) NOPASSWD: /usr/bin/arch-nspawn" > /etc/sudoers.d/arch-nspawn && \
    chmod 440 /etc/sudoers.d/arch-nspawn

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