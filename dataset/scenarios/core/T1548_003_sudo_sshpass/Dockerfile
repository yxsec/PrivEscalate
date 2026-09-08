FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_sshpass
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/sshpass as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and sshpass
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        sshpass \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify sshpass is installed
RUN which sshpass && ls -la /usr/bin/sshpass

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# sshpass can be abused to spawn a shell when run via sudo:
#   sudo sshpass /bin/sh
# sshpass will execute the command passed to it, and since it runs as root
# via sudo, the spawned shell will be a root shell.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/sshpass" > /etc/sudoers.d/sshpass && \
    chmod 440 /etc/sudoers.d/sshpass

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