FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-server \
        groff-base \
        openssl \
        python3 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Set SUID on soelim - the vulnerability
RUN chmod u+s /usr/bin/soelim

RUN ls -la /usr/bin/soelim | grep -q "rws" && echo "SUID bit confirmed on soelim"

# Make /etc/shadow readable by root only (default), so SUID soelim can read it but lowpriv cannot
RUN chmod 0640 /etc/shadow

# Ensure /etc/passwd is NOT world-writable (normal permissions)
RUN chmod 0644 /etc/passwd

RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]