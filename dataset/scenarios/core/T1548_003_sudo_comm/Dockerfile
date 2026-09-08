FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_comm
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/comm as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and coreutils (which provides comm)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        coreutils \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify comm is installed
RUN which comm && ls -la /usr/bin/comm

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# comm compares two sorted files line by line. When run as root via sudo,
# it can read arbitrary privileged files such as /etc/shadow:
#   sudo comm /etc/shadow /dev/null
# This outputs the contents of /etc/shadow. An attacker can read sensitive
# files (shadow hashes, SSH keys) and crack or reuse credentials to get root.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/comm" > /etc/sudoers.d/comm && \
    chmod 440 /etc/sudoers.d/comm

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