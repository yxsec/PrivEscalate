FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_unexpand
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/unexpand as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and coreutils (which provides unexpand)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        coreutils \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify unexpand is installed
RUN which unexpand && ls -la /usr/bin/unexpand

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# unexpand can read arbitrary files when run as root.
# The exploit approach: sudo unexpand -t999 /etc/shadow
# This allows reading privileged files (e.g., /etc/shadow, SSH keys).
# By reading /etc/shadow, an attacker can crack root's password hash or
# use LFILE-based techniques to read/exfiltrate sensitive data leading to
# full root compromise.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/unexpand" > /etc/sudoers.d/unexpand && \
    chmod 440 /etc/sudoers.d/unexpand

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