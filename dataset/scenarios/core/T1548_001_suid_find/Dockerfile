FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on find
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on /usr/bin/find allows
#   privilege escalation via: find . -exec /bin/sh -p \; -quit
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server and findutils (provides find)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-server \
        findutils \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Inject vulnerability: set SUID bit on find
RUN chmod u+s /usr/bin/find

# Verify vulnerability is in place
RUN ls -la /usr/bin/find | grep -q "rws" && echo "SUID bit confirmed on find"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]