FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server \
    php-cli \
    libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /run/sshd

RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

RUN useradd -m -s /bin/bash lowpriv && \
    echo 'lowpriv:password123' | chpasswd

# /usr/bin/php is a symlink; setcap requires a regular file.
# Find the actual php binary and set the capability on it.
RUN setcap cap_setuid+ep $(readlink -f /usr/bin/php)

# Verify the capability is set
RUN getcap $(readlink -f /usr/bin/php)

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D"]