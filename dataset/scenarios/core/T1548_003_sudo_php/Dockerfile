FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_php
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/php as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and PHP CLI
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        php-cli \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify php is installed
RUN which php && ls -la /usr/bin/php

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# php can execute arbitrary system commands when run as root:
#   sudo php -r 'system("/bin/sh -i");'
# This spawns an interactive root shell.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/php" > /etc/sudoers.d/php && \
    chmod 440 /etc/sudoers.d/php

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