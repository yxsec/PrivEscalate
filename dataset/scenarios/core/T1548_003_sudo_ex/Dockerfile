FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_ex
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/ex as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and vim (which provides ex)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        vim \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify ex is installed
RUN which ex && ls -la /usr/bin/ex

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# ex is an extended line editor (part of vim). When run as root via sudo,
# the user can escape to a shell with:
#   sudo ex -c ':!/bin/sh'
# This drops the user into a root shell.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/ex" > /etc/sudoers.d/ex && \
    chmod 440 /etc/sudoers.d/ex

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