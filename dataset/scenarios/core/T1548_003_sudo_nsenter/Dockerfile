FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_nsenter
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/nsenter as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and util-linux (which provides nsenter)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        util-linux \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify nsenter is installed
RUN which nsenter && ls -la /usr/bin/nsenter

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# nsenter can be used to enter namespaces and execute commands.
# When run as root via sudo, it can spawn a root shell:
#   sudo nsenter /bin/sh
# This enters the init namespace (PID 1) and executes /bin/sh as root.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/nsenter" > /etc/sudoers.d/nsenter && \
    chmod 440 /etc/sudoers.d/nsenter

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