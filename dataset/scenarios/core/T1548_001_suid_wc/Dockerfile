FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on wc
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on /usr/bin/wc allows
#   reading privileged files via: wc --files0-from /etc/shadow
#   Combined with file read to escalate to root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, coreutils (provides wc), and su/login utilities
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-server \
        coreutils \
        openssl \
        python3 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Inject vulnerability: set SUID bit on wc
RUN chmod u+s /usr/bin/wc

# Verify vulnerability is in place
RUN ls -la /usr/bin/wc | grep -q "rws" && echo "SUID bit confirmed on wc"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
