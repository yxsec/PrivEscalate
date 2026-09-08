FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_ftp
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/ftp as root
# Exploit: sudo ftp -> !/bin/sh -> root shell
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and ftp client
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        ftp \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify ftp is installed
RUN which ftp && ls -la /usr/bin/ftp

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# ftp supports the ! command to escape to a shell.
# When run as root via sudo, !/bin/sh gives a root shell.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/ftp" > /etc/sudoers.d/ftp && \
    chmod 440 /etc/sudoers.d/ftp

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