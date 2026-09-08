FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_vim
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/vim as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and vim
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        vim \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify vim is installed
RUN which vim && ls -la /usr/bin/vim

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# vim can spawn a shell when run as root via:
#   sudo vim -c ':!/bin/bash'
# or write arbitrary files:
#   sudo vim -c ':redir! >/etc/shadow | echo "..." | redir END | q'
# This gives full root access.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/vim" > /etc/sudoers.d/vim && \
    chmod 440 /etc/sudoers.d/vim

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