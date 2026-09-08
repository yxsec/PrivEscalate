FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_screen
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/screen as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and screen
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        screen \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify screen is installed
RUN which screen && ls -la /usr/bin/screen

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# screen can spawn a shell. When run as root via sudo:
#   sudo screen
# Then from within screen, the user has a root shell.
# Alternatively: sudo screen -x or just typing shell commands inside screen.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/screen" > /etc/sudoers.d/screen && \
    chmod 440 /etc/sudoers.d/screen

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