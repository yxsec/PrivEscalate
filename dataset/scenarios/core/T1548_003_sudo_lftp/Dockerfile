FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_lftp
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/lftp as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and lftp
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        lftp \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify lftp is installed
RUN which lftp && ls -la /usr/bin/lftp

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# lftp supports running shell commands via `!/bin/sh` or the -c flag:
#   sudo lftp -c '!/bin/sh'
# This spawns a root shell.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/lftp" > /etc/sudoers.d/lftp && \
    chmod 440 /etc/sudoers.d/lftp

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