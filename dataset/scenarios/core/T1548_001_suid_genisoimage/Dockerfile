FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, genisoimage, and utilities needed for exploit verification
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-server \
        genisoimage \
        coreutils \
        openssl \
        xxd \
        mount \
        util-linux \
        python3 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Inject vulnerability: set SUID bit on genisoimage
RUN chmod u+s /usr/bin/genisoimage

# Also set SUID on a small helper: compile a C program that copies a file as root
# This simulates a realistic scenario where SUID genisoimage can be leveraged
# We keep cp available and install needed tools
RUN ls -la /usr/bin/genisoimage | grep -q "rws" && echo "SUID bit confirmed on genisoimage"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]