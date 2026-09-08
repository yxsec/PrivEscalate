FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        zathura \
        xvfb \
        xdotool \
        dbus-x11 \
        coreutils \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

RUN which zathura && ls -la /usr/bin/zathura

RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/zathura" > /etc/sudoers.d/zathura && \
    chmod 440 /etc/sudoers.d/zathura

RUN visudo -c

RUN chmod u+s /usr/bin/sudo

RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]