FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_base58
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/base58 as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and base58
# base58 is available via python3-base58 which provides a CLI tool,
# or we can install it via pip. Let's use pip to get the base58 CLI.
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        python3 \
        python3-pip \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Install base58 Python package which provides the base58 CLI tool
RUN pip3 install --break-system-packages base58

# Ensure base58 is available at /usr/bin/base58 (pip may install to /usr/local/bin)
RUN if [ ! -f /usr/bin/base58 ]; then \
        ln -s $(which base58) /usr/bin/base58; \
    fi

# Verify base58 is installed
RUN which base58 && ls -la /usr/bin/base58

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# base58 can encode/decode files when run as root. The exploit approach:
#   LFILE=/etc/shadow
#   sudo base58 "$LFILE" | base58 --decode
# This allows reading any file as root. By reading /etc/shadow and then
# crafting a new passwd/shadow entry, or reading SSH private keys,
# an attacker can escalate to root.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/base58" > /etc/sudoers.d/base58 && \
    chmod 440 /etc/sudoers.d/base58

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