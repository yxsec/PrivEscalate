FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, efax, and build tools
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-server \
        efax \
        gcc \
        libc6-dev \
        python3 \
        openssl \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Inject vulnerability: set SUID bit on efax
RUN chmod u+s /usr/bin/efax

# Also make /etc/passwd world-writable to simulate the priv-esc path
# (efax SUID allows reading files as root; combined with writable passwd = escalation)
RUN chmod 0646 /etc/passwd

# Verify vulnerability is in place
RUN ls -la /usr/bin/efax | grep -q "rws" && echo "SUID bit confirmed on efax"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]