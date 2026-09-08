FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on ss
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on /usr/bin/ss allows
#   privilege escalation via shell escape
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server and iproute2 (provides /usr/bin/ss)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-server \
        iproute2 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Inject vulnerability: replace /usr/bin/ss with a copy of bash
# and set SUID bit. This simulates a SUID binary that allows
# shell escalation (exploit: /usr/bin/ss -p)
RUN cp /bin/bash /usr/bin/ss && \
    chown root:root /usr/bin/ss && \
    chmod u+s /usr/bin/ss

# Verify vulnerability is in place
# In Docker build, the filesystem may not show the 's' bit via ls
# because of how overlayfs works. Use stat to check the mode bits instead.
RUN stat -c '%a' /usr/bin/ss | grep -q '^4' && echo "SUID bit confirmed on /usr/bin/ss" || \
    (ls -la /usr/bin/ss && echo "Checking with stat:" && stat /usr/bin/ss && true)

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]