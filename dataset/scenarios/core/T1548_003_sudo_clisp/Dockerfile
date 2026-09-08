FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_clisp
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/clisp as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and clisp
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        clisp \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify clisp is installed
RUN which clisp && ls -la /usr/bin/clisp

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# clisp can execute arbitrary shell commands when run as root:
#   sudo clisp -x '(ext:run-shell-command "/bin/sh")(ext:exit)'
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/clisp" > /etc/sudoers.d/clisp && \
    chmod 440 /etc/sudoers.d/clisp

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