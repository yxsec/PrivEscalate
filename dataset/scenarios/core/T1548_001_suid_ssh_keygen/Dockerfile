FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on ssh-keygen
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on /usr/bin/ssh-keygen allows
#   privilege escalation via shared library loading.
#   GTFOBins documents that ssh-keygen can load shared libs
#   via: ssh-keygen -D ./lib.so
#   With SUID, the loaded library runs as root.
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, openssh-client (provides ssh-keygen), and gcc for compiling exploit .so
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        openssh-client \
        gcc \
        libc6-dev \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Inject vulnerability: set SUID bit on ssh-keygen
RUN chmod u+s /usr/bin/ssh-keygen

# Verify vulnerability is in place
RUN ls -la /usr/bin/ssh-keygen | grep -q "rws" && echo "SUID bit confirmed on ssh-keygen"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]