FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-server \
        grep \
        openssl \
        gcc \
        libc6-dev \
        coreutils \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Create a small C program that acts as SUID egrep but also allows
# file writing via a special mode, simulating a vulnerable SUID binary
# Actually, let's create a proper SUID scenario:
# We'll make a SUID C wrapper that can read files (like grep) but
# also we'll place a known root password so the exploit can su after reading shadow.

# Replace egrep with binary copy of grep so SUID works
RUN rm -f /usr/bin/egrep && \
    cp /usr/bin/grep /usr/bin/egrep && \
    chmod u+s /usr/bin/egrep

# Also create a small SUID helper that allows writing (simulating a more
# powerful misconfiguration). We'll use a different approach:
# Create a SUID cp binary so exploit can overwrite /etc/passwd
RUN cp /usr/bin/cp /usr/local/bin/suid_cp && \
    chmod u+s /usr/local/bin/suid_cp

# Harden base image
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Verify vulnerability
RUN ls -la /usr/bin/egrep | grep -q "rws" && echo "SUID bit confirmed on egrep"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]