FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_debugfs
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/debugfs as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and e2fsprogs (which provides debugfs)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        e2fsprogs \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify debugfs is installed
RUN which debugfs && ls -la /usr/sbin/debugfs

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# debugfs has an interactive shell that supports running system commands
# via the ! (bang) escape. When run as root via sudo, the attacker can:
#   sudo debugfs
#   debugfs: !/bin/sh
# This drops into a root shell.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/sbin/debugfs" > /etc/sudoers.d/debugfs && \
    chmod 440 /etc/sudoers.d/debugfs

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