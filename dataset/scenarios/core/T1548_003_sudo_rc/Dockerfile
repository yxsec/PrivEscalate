FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_rc
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/rc as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and rc (Plan 9 shell from the rc package)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        rc \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify rc is installed
RUN which rc && ls -la /usr/bin/rc

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# rc is a shell (Plan 9 shell). When run as root via sudo, it provides
# an interactive root shell directly:
#   sudo rc
# This immediately drops the user into a root shell.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/rc" > /etc/sudoers.d/rc && \
    chmod 440 /etc/sudoers.d/rc

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