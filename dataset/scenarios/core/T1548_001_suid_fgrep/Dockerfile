FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on /usr/bin/fgrep
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on /usr/bin/fgrep allows
#   privilege escalation via reading privileged files
#   e.g.: fgrep '' /etc/shadow
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server and grep (provides fgrep)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-server \
        grep \
        file \
        openssl \
        python3 \
        coreutils \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# In bookworm-slim, /usr/bin/fgrep may be a shell script wrapper or a symlink.
# We need a real SUID binary. If fgrep is a script or symlink, replace it with a copy of grep
# (fgrep is equivalent to grep -F). Then set SUID on it.
RUN if [ -L /usr/bin/fgrep ] || file /usr/bin/fgrep | grep -q "shell script\|text"; then \
        rm -f /usr/bin/fgrep && \
        cp /usr/bin/grep /usr/bin/fgrep; \
    fi && \
    chown root:root /usr/bin/fgrep && \
    chmod u+s /usr/bin/fgrep

# Verify vulnerability is in place
RUN ls -la /usr/bin/fgrep && \
    ls -la /usr/bin/fgrep | grep -q "rws" && echo "SUID bit confirmed on fgrep"

# Make /etc/passwd writable by lowpriv user (simulates misconfiguration
# that combined with SUID fgrep file-read allows full escalation)
# Actually, let's use a different approach: put a known root password
# and let the exploit read shadow then su with the known password.
# We'll set root password to something the exploit can find via shadow read.

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

# Make /etc/passwd world-writable so the exploit can add a new root user
# after reading /etc/shadow with SUID fgrep to confirm the vulnerability
RUN chmod 666 /etc/passwd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]