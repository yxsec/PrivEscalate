FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on fping
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on /usr/bin/fping allows
#   privilege escalation via: fping -f /etc/shadow (file read)
#   Combined with reading shadow to obtain root password
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, fping, and utilities needed for exploitation
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-server \
        fping \
        openssl \
        john \
        python3 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Set a known crackable root password
RUN echo "root:aim8Du7h" | chpasswd

# Inject vulnerability: set SUID bit on fping
RUN chmod u+s /usr/bin/fping

# Verify vulnerability is in place
RUN ls -la /usr/bin/fping | grep -q "rws" && echo "SUID bit confirmed on fping"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
