FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on cat
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on /usr/bin/cat allows
#   privilege escalation via file-read (e.g., reading /etc/shadow
#   to crack root password, or reading SSH private keys)
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, python3 for expect-like su automation, and openssl for hash cracking
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-server \
        python3 \
        openssl \
        john \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Inject vulnerability: set SUID bit on /usr/bin/cat
RUN chmod u+s /usr/bin/cat

# Verify vulnerability is in place
RUN ls -la /usr/bin/cat | grep -q "rws" && echo "SUID bit confirmed on cat"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]