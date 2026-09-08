FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_mawk
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/mawk as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and mawk
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        mawk \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify mawk is installed
RUN which mawk && ls -la /usr/bin/mawk

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# mawk can spawn a shell when run as root via:
#   sudo mawk 'BEGIN {system("/bin/sh")}'
# This gives an interactive root shell immediately.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/mawk" > /etc/sudoers.d/mawk && \
    chmod 440 /etc/sudoers.d/mawk

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