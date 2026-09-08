FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_tar
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/tar as root
# Exploit: sudo tar cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and tar (tar is usually present but ensure it)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        tar \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify tar is installed
RUN which tar && ls -la /usr/bin/tar

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# tar's --checkpoint-action=exec allows arbitrary command execution.
# When run as root via sudo, this gives a root shell:
#   sudo tar cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/tar" > /etc/sudoers.d/tar && \
    chmod 440 /etc/sudoers.d/tar

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