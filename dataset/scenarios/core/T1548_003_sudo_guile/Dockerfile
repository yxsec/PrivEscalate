FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_guile
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/guile as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and guile
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        guile-3.0 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify guile is installed
RUN which guile && ls -la /usr/bin/guile

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# guile can execute arbitrary system commands when run as root:
#   sudo guile -c '(system "/bin/sh")'
# This spawns a root shell directly.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/guile" > /etc/sudoers.d/guile && \
    chmod 440 /etc/sudoers.d/guile

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