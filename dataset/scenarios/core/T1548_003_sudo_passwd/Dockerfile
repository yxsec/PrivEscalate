FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_passwd
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/passwd as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and passwd (passwd is in the 'passwd' package)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        passwd \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify passwd is installed
RUN which passwd && ls -la /usr/bin/passwd

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# passwd when run as root via sudo can change the root password without
# knowing the current password. The exploit approach:
#   sudo passwd root
# This allows the attacker to set a new root password and then su to root.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/passwd" > /etc/sudoers.d/passwd && \
    chmod 440 /etc/sudoers.d/passwd

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