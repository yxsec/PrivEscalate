FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on expect
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on /usr/bin/expect allows
#   privilege escalation via: expect -c 'spawn /bin/sh -p; interact'
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server and expect
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-server \
        expect \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Inject vulnerability: set SUID bit on expect
RUN chmod u+s /usr/bin/expect

# Verify vulnerability is in place
RUN ls -la /usr/bin/expect | grep -q "rws" && echo "SUID bit confirmed on expect"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]