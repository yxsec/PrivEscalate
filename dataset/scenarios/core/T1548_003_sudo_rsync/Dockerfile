FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_rsync
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/rsync as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and rsync
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        rsync \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify rsync is installed
RUN which rsync && ls -la /usr/bin/rsync

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# rsync's -e flag allows specifying a remote shell command. When run as root via sudo,
# this can be abused to spawn a root shell:
#   sudo rsync -e '/bin/sh -c "/bin/sh 0<&2 1>&2"' x:x
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/rsync" > /etc/sudoers.d/rsync && \
    chmod 440 /etc/sudoers.d/rsync

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