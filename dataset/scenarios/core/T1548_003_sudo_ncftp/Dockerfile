FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_ncftp
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/ncftp as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and ncftp
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        ncftp \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify ncftp is installed
RUN which ncftp && ls -la /usr/bin/ncftp

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# ncftp has an interactive shell that allows executing system commands via
# the ! (bang) escape. When run as root via sudo, the user can execute:
#   sudo ncftp
#   !/bin/sh
# This drops into a root shell.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/ncftp" > /etc/sudoers.d/ncftp && \
    chmod 440 /etc/sudoers.d/ncftp

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