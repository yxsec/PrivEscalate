FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_ar
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/ar as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and binutils (which provides ar)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        binutils \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify ar is installed
RUN which ar && ls -la /usr/bin/ar

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# ar can read and write arbitrary files when run as root.
# Exploit approach:
#   sudo ar r /tmp/exploit.a /etc/shadow   (archive a privileged file)
#   sudo ar p /tmp/exploit.a               (print contents to stdout)
# This allows reading sensitive files like /etc/shadow.
# For full root compromise, one can craft a modified /etc/passwd or /etc/shadow,
# archive it, then extract it to overwrite the original, achieving uid=0.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/ar" > /etc/sudoers.d/ar && \
    chmod 440 /etc/sudoers.d/ar

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