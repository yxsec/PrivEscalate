FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_nohup
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/nohup as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and coreutils (which provides nohup)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        coreutils \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify nohup is installed
RUN which nohup && ls -la /usr/bin/nohup

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# nohup can execute arbitrary commands. When run as root via sudo:
#   sudo nohup /bin/sh -c '/bin/sh </dev/tty >/dev/tty 2>/dev/tty'
# This spawns a root shell.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/nohup" > /etc/sudoers.d/nohup && \
    chmod 440 /etc/sudoers.d/nohup

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