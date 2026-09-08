FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on batcat
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on /usr/bin/batcat allows
#   privilege escalation via file read or shell escape
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server and bat (provides batcat)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-server \
        bat \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Inject vulnerability: set SUID bit on batcat
RUN chmod u+s /usr/bin/batcat

# Verify vulnerability is in place
RUN ls -la /usr/bin/batcat | grep -q "rws" && echo "SUID bit confirmed on batcat"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]