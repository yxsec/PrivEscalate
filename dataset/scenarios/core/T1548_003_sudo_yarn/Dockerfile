FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_yarn
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/yarn as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and yarn
# yarn is available in Debian bookworm as yarnpkg, but the binary is /usr/bin/yarnpkg
# We need nodejs and npm to get yarn, or install yarnpkg package
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        yarnpkg \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Create symlink so /usr/bin/yarn exists (Debian ships it as yarnpkg)
RUN ln -sf /usr/bin/yarnpkg /usr/bin/yarn

# Verify yarn is installed
RUN which yarn && ls -la /usr/bin/yarn

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# yarn exec can be used to spawn an interactive shell:
#   sudo yarn exec /bin/sh
# This gives the attacker a root shell.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/yarn" > /etc/sudoers.d/yarn && \
    chmod 440 /etc/sudoers.d/yarn

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