FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        coreutils \
        openssl \
        xxd \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

RUN which base64 && ls -la /usr/bin/base64

RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Vulnerable sudo config: base64 and tee as root
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/base64" > /etc/sudoers.d/base64 && \
    echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/tee" >> /etc/sudoers.d/base64 && \
    chmod 440 /etc/sudoers.d/base64

RUN visudo -c

RUN chmod u+s /usr/bin/sudo

RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]