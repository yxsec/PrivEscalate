FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        xpad \
        xvfb \
        gcc \
        libc6-dev \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

RUN which xpad && ls -la /usr/bin/xpad

RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Sudo misconfiguration: allows running xpad as root with env_keep for LD_PRELOAD
RUN echo 'Defaults    env_keep += "LD_PRELOAD"' > /etc/sudoers.d/xpad && \
    echo 'lowpriv ALL=(root) NOPASSWD: /usr/bin/xpad' >> /etc/sudoers.d/xpad && \
    chmod 440 /etc/sudoers.d/xpad

RUN visudo -c

RUN chmod u+s /usr/bin/sudo

RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]