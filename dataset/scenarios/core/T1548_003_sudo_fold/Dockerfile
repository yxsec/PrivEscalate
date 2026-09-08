FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_fold
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/fold as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and coreutils (which provides fold)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        coreutils \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify fold is installed
RUN which fold && ls -la /usr/bin/fold

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# fold can read arbitrary files when run as root. The exploit approach:
#   sudo fold -w999 /etc/shadow
# This allows reading any privileged file (e.g., /etc/shadow, SSH private keys).
# An attacker can read /etc/shadow, crack root's password hash, or read
# other sensitive files to escalate privileges to root.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/fold" > /etc/sudoers.d/fold && \
    chmod 440 /etc/sudoers.d/fold

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