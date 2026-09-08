FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_emacs
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/emacs as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and emacs
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        emacs-nox \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify emacs is installed
RUN which emacs && ls -la /usr/bin/emacs

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# emacs can spawn a shell when run as root via:
#   sudo emacs -Q -nw --eval '(term "/bin/sh")'
# This gives an interactive root shell from within emacs.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/emacs" > /etc/sudoers.d/emacs && \
    chmod 440 /etc/sudoers.d/emacs

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