FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_7z
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/7z as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and 7zip
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        p7zip-full \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify 7z is installed
RUN which 7z && ls -la /usr/bin/7z

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# 7z can read arbitrary files when run as root. The exploit approach:
#   sudo 7z a -ttar -an -so /etc/shadow
# This archives a file to stdout in tar format, allowing reading of privileged files.
# Combined with writing capabilities, this can lead to full root compromise
# by overwriting /etc/passwd or /etc/shadow, or reading SSH keys.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/7z" > /etc/sudoers.d/7z && \
    chmod 440 /etc/sudoers.d/7z

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