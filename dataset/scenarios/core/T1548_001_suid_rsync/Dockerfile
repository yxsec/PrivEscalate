FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on rsync
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on /usr/bin/rsync allows
#   privilege escalation via: rsync -e 'sh -p -c "sh -p 0<&2 1>&2"' 127.0.0.1:/dev/null
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server and rsync
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-server \
        rsync \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Inject vulnerability: set SUID bit on rsync
RUN chmod u+s /usr/bin/rsync

# Verify vulnerability is in place
RUN ls -la /usr/bin/rsync | grep -q "rws" && echo "SUID bit confirmed on rsync"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]