FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_tmux
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/tmux as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and tmux
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        tmux \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify tmux is installed
RUN which tmux && ls -la /usr/bin/tmux

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# tmux can spawn arbitrary commands. When run as root via sudo:
#   sudo tmux -c /bin/sh
# This gives an interactive root shell immediately.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/tmux" > /etc/sudoers.d/tmux && \
    chmod 440 /etc/sudoers.d/tmux

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