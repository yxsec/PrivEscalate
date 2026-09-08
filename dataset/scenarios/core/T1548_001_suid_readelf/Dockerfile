FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server and binutils (provides readelf)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-server \
        binutils \
        openssl \
        coreutils \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Inject vulnerability: set SUID bit on readelf
RUN REAL_READELF=$(readlink -f /usr/bin/readelf) && \
    chmod u+s "$REAL_READELF"

# Also make a SUID C wrapper that uses readelf to write files as root
# Actually, let's create a simpler path: make a SUID copy helper
# The key vuln is SUID readelf can read any file as root

# Verify vulnerability is in place
RUN REAL_READELF=$(readlink -f /usr/bin/readelf) && \
    ls -la "$REAL_READELF" && \
    ls -la "$REAL_READELF" | grep -q "^-..s" && \
    echo "SUID bit confirmed on readelf"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]