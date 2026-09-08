FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_npm
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/npm as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and npm (nodejs)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        npm \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify npm is installed
RUN which npm && ls -la /usr/bin/npm

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# npm can be used to spawn a shell when run as root via sudo.
# Exploit: sudo npm exec /bin/sh
# or: echo '{"scripts":{"preinstall":"/bin/sh"}}' > /tmp/package.json && cd /tmp && sudo npm install
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/npm" > /etc/sudoers.d/npm && \
    chmod 440 /etc/sudoers.d/npm

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