FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_plymouth
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/plymouth as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and plymouth
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        plymouth \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify plymouth is installed
RUN which plymouth && ls -la /usr/bin/plymouth

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# plymouth can execute arbitrary commands via:
#   sudo plymouth ask-for-password --prompt=x --command=/bin/sh
# The --command flag specifies a command to run when a password is entered,
# but in certain invocations it can be abused to spawn a root shell.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/plymouth" > /etc/sudoers.d/plymouth && \
    chmod 440 /etc/sudoers.d/plymouth

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