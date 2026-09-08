FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on grep
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on /usr/bin/grep allows
#   privilege escalation by reading sensitive files like
#   /etc/shadow, SSH keys, etc.
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, grep, and expect (for automating su)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-server \
        grep \
        expect \
        coreutils \
        util-linux \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Set a known root password (so reading /etc/shadow is exploitable)
RUN echo "root:root" | chpasswd

# Inject vulnerability: set SUID bit on /usr/bin/grep
RUN chmod u+s /usr/bin/grep

# Verify vulnerability is in place
RUN ls -la /usr/bin/grep | grep -q "rws" && echo "SUID bit confirmed on grep"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
