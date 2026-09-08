FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_restic
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/restic as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and restic
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        restic \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify restic is installed
RUN which restic && ls -la /usr/bin/restic

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# restic allows specifying RESTIC_PASSWORD_COMMAND which executes an arbitrary command.
# When run via sudo, the password command runs as root, giving a root shell:
#   sudo RESTIC_PASSWORD_COMMAND='sh -c "sh 0<&2 1<&2"' restic backup /dev/null --repo /tmp/backup
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/restic" > /etc/sudoers.d/restic && \
    chmod 440 /etc/sudoers.d/restic

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