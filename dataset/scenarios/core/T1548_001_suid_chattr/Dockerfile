FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on chattr
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on /usr/bin/chattr allows
#   privilege escalation. The /etc/passwd file has the immutable
#   attribute set but is world-writable, so removing the immutable
#   flag via SUID chattr allows overwriting it.
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, e2fsprogs (provides chattr), and openssl
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-server \
        e2fsprogs \
        openssl \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Inject vulnerability: set SUID bit on chattr
RUN chmod u+s /usr/bin/chattr

# Make /etc/passwd world-writable.
# The immutable flag will be set at container start (requires runtime capabilities).
RUN chmod 666 /etc/passwd

# Verify vulnerability is in place
RUN ls -la /usr/bin/chattr | grep -q "rws" && echo "SUID bit confirmed on chattr"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

# Create entrypoint script that sets immutable flag at runtime then starts sshd
RUN printf '#!/bin/bash\nchattr +i /etc/passwd 2>/dev/null || true\nexec /usr/sbin/sshd -D\n' > /entrypoint.sh && \
    chmod +x /entrypoint.sh

EXPOSE 22
CMD ["/entrypoint.sh"]
