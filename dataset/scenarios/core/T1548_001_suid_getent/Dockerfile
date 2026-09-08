FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-server \
        openssl \
        python3 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Inject vulnerability: set SUID bit on getent
RUN chmod u+s /usr/bin/getent

# Make /etc/passwd world-writable so the exploit can add a root-equivalent user
# This simulates a misconfiguration that pairs with SUID getent file-read
RUN chmod 666 /etc/passwd

RUN ls -la /usr/bin/getent | grep -q "rws" && echo "SUID bit confirmed on getent"

RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
