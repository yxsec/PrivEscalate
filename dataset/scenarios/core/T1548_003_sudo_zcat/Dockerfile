FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        gzip \
        python3 \
        openssl \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

RUN which zcat && ls -la /usr/bin/zcat

RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Vulnerable sudo rule: allows running zcat as root without password
# Also allow tee as root to enable file write (simulating a broader misconfiguration)
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/zcat" > /etc/sudoers.d/zcat && \
    echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/tee" >> /etc/sudoers.d/zcat && \
    chmod 440 /etc/sudoers.d/zcat

RUN visudo -c

RUN chmod u+s /usr/bin/sudo

RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]