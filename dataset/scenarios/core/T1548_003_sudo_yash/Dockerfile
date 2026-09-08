FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_yash
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/yash as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and yash
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        yash \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify yash is installed
RUN which yash && ls -la /usr/bin/yash

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# yash is a full-featured shell. When run as root via sudo, it provides
# an interactive root shell directly:
#   sudo yash
# This immediately gives uid=0 access.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/yash" > /etc/sudoers.d/yash && \
    chmod 440 /etc/sudoers.d/yash

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