FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_posh
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/posh as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and posh (Policy-compliant Ordinary SHell)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        posh \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify posh is installed
RUN which posh && ls -la /usr/bin/posh

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# posh is a shell, so running it as root via sudo gives an interactive root shell.
# Exploit: sudo posh  (then you have a root shell)
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/posh" > /etc/sudoers.d/posh && \
    chmod 440 /etc/sudoers.d/posh

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