FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_wg-quick
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/wg-quick as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and wireguard-tools (provides wg-quick)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        wireguard-tools \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify wg-quick is installed
RUN which wg-quick && ls -la /usr/bin/wg-quick

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# wg-quick is a bash script that sources configuration files.
# The config file can contain a PostUp directive that executes arbitrary commands.
# Exploit approach:
#   1. Create a rogue WireGuard config: /tmp/evil.conf with PostUp = /bin/bash
#   2. Run: sudo wg-quick up /tmp/evil.conf
#   This causes wg-quick to execute /bin/bash as root via the PostUp hook.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/wg-quick" > /etc/sudoers.d/wg-quick && \
    chmod 440 /etc/sudoers.d/wg-quick

# Verify sudo configuration
RUN visudo -c

# Keep SUID on sudo
RUN chmod u+s /usr/bin/sudo

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]