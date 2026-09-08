FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on rpmquery (rpm)
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on /usr/bin/rpmquery allows
#   privilege escalation via: rpmquery --eval '%{lua:os.execute("/bin/sh -p")}'
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server and rpm (provides rpmquery)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        rpm \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# rpmquery may be a symlink to rpm or a standalone binary; find the real path
# and set SUID on both the symlink target and ensure rpmquery is accessible
RUN RPMQUERY_PATH=$(which rpmquery 2>/dev/null || echo "/usr/bin/rpmquery") && \
    REAL_PATH=$(readlink -f "$RPMQUERY_PATH") && \
    chmod u+s "$REAL_PATH" && \
    echo "SUID set on $REAL_PATH"

# Also set SUID on /usr/bin/rpm in case rpmquery is a symlink to it
RUN chmod u+s /usr/bin/rpm 2>/dev/null || true && \
    chmod u+s /usr/bin/rpmquery 2>/dev/null || true

# Verify vulnerability is in place
RUN ls -la /usr/bin/rpmquery && \
    ls -la $(readlink -f /usr/bin/rpmquery) | grep -q "rws" && \
    echo "SUID bit confirmed on rpmquery"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]