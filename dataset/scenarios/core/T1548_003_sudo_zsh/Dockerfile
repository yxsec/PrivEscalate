FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_zsh
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/zsh as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and zsh
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        zsh \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify zsh is installed
RUN which zsh && ls -la /usr/bin/zsh

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# zsh is a full interactive shell. When run as root via sudo,
# it immediately gives an interactive root shell.
# Exploit: sudo zsh
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/zsh" > /etc/sudoers.d/zsh && \
    chmod 440 /etc/sudoers.d/zsh

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