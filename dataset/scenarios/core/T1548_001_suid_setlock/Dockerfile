FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on setlock
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on /usr/bin/setlock allows
#   privilege escalation via: setlock /tmp/lock /bin/sh -p
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server and daemontools (provides setlock)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-server \
        daemontools \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# setlock may be installed in /usr/bin or /usr/bin/setlock depending on package
# daemontools on Debian bookworm installs to /usr/bin/setlock
# If not at /usr/bin/setlock, find and symlink it
RUN which setlock || find / -name setlock -type f 2>/dev/null
RUN if [ ! -f /usr/bin/setlock ]; then \
        SETLOCK_PATH=$(find / -name setlock -type f 2>/dev/null | head -1) && \
        if [ -n "$SETLOCK_PATH" ]; then \
            cp "$SETLOCK_PATH" /usr/bin/setlock; \
        fi; \
    fi

# Inject vulnerability: set SUID bit on setlock
RUN chmod u+s /usr/bin/setlock

# Verify vulnerability is in place
RUN ls -la /usr/bin/setlock | grep -q "rws" && echo "SUID bit confirmed on setlock"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]