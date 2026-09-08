FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        autoconf \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

RUN which autoconf && ls -la /usr/bin/autoconf

RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Configure sudo vulnerability - allow env vars to be passed through
RUN echo 'lowpriv ALL=(root) NOPASSWD: SETENV: /usr/bin/autoconf' > /etc/sudoers.d/autoconf && \
    chmod 440 /etc/sudoers.d/autoconf

RUN visudo -c

RUN chmod u+s /usr/bin/sudo

RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
