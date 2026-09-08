FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_script
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/script as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and bsdutils (which provides /usr/bin/script)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        bsdutils \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify script is installed
RUN which script && ls -la /usr/bin/script

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# script can spawn an interactive shell when run as root:
#   sudo script -q /dev/null
# This gives the user a root shell immediately.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/script" > /etc/sudoers.d/script && \
    chmod 440 /etc/sudoers.d/script

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