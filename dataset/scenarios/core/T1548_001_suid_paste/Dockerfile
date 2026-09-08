FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on paste
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on /usr/bin/paste allows
#   privilege escalation via reading privileged files
#   e.g.: paste /etc/shadow
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, coreutils (provides /usr/bin/paste), and openssl for password hashing
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-server \
        coreutils \
        openssl \
        gcc \
        libc6-dev \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Inject vulnerability: set SUID bit on paste
RUN chmod u+s /usr/bin/paste

# Verify vulnerability is in place
RUN ls -la /usr/bin/paste | grep -q "rws" && echo "SUID bit confirmed on paste"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
