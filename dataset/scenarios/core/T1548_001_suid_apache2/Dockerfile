FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        apache2 \
        gcc \
        libc6-dev \
        libapr1-dev \
        libaprutil1-dev \
        apache2-dev \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Copy apache2 to /usr/bin/apache2
RUN cp /usr/sbin/apache2 /usr/bin/apache2

# Harden base image
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Inject vulnerability: set SUID bit on /usr/bin/apache2
RUN chmod u+s /usr/bin/apache2

# Verify vulnerability is in place
RUN ls -la /usr/bin/apache2 | grep -q "rws" && echo "SUID bit confirmed on /usr/bin/apache2"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
