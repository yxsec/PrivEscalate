FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on rc (Plan 9 shell)
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on /usr/bin/rc allows
#   privilege escalation via: rc -c '/bin/sh -p'
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server and rc (Plan 9 shell from plan9port or 9base)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-server \
        9base \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# 9base installs rc to /usr/lib/plan9/bin/rc — create a symlink if needed
# and set SUID on the actual binary
RUN if [ -f /usr/lib/plan9/bin/rc ]; then \
        ln -sf /usr/lib/plan9/bin/rc /usr/bin/rc; \
        chmod u+s /usr/lib/plan9/bin/rc; \
    elif [ -f /usr/bin/rc ]; then \
        chmod u+s /usr/bin/rc; \
    fi

# Verify vulnerability is in place
RUN ls -la /usr/lib/plan9/bin/rc | grep -q "rws" && echo "SUID bit confirmed on rc"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]