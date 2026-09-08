FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        gimp \
        xvfb \
        xauth \
        dbus-x11 \
        gcc \
        coreutils \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

RUN which gimp && ls -la /usr/bin/gimp

RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/gimp" > /etc/sudoers.d/gimp && \
    chmod 440 /etc/sudoers.d/gimp

RUN visudo -c

RUN chmod u+s /usr/bin/sudo

RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
