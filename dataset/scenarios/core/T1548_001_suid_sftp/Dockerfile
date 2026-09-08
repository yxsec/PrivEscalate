FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on sftp
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on /usr/bin/sftp allows
#   privilege escalation via ProxyCommand executing as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server and openssh-client (provides /usr/bin/sftp)
# Also install gcc so exploit can compile a small C helper
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        openssh-client \
        gcc \
        libc6-dev \
        coreutils \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Inject vulnerability: set SUID bit on sftp
RUN chmod u+s /usr/bin/sftp

# Verify vulnerability is in place
RUN ls -la /usr/bin/sftp | grep -q "rws" && echo "SUID bit confirmed on sftp"

# Configure SSH - enable localhost connections for sftp
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

# Generate host keys so sshd can start
RUN ssh-keygen -A

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]