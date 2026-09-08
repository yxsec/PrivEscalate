FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_service
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/service as root
# Known exploit: service ../../bin/sh
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and the service utility (part of init-system-helpers)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        init-system-helpers \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify service is installed
RUN which service && ls -la /usr/sbin/service

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# The `service` command can be abused to spawn a shell via path traversal:
#   sudo service ../../bin/sh
# This works because service passes the argument to an init script path,
# and the path traversal resolves to /bin/sh which gets executed as root.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/sbin/service" > /etc/sudoers.d/service && \
    chmod 440 /etc/sudoers.d/service

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