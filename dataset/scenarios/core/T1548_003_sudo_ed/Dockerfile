FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_ed
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/ed as root
# Exploit: sudo ed -> !/bin/sh -> root shell
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and ed
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        ed \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify ed is installed
RUN which ed && ls -la /usr/bin/ed

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# ed is a line editor that supports shell escape via !/bin/sh
# When run as root via sudo, the spawned shell inherits root privileges.
# Exploit:
#   sudo ed
#   !/bin/sh
#   (now have root shell)
#   q
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/ed" > /etc/sudoers.d/ed && \
    chmod 440 /etc/sudoers.d/ed

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