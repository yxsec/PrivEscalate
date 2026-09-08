FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        yelp \
        man-db \
        dbus-x11 \
        xvfb \
        coreutils \
        openssl \
        python3 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

RUN which yelp && ls -la /usr/bin/yelp

RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Set a known root password so we can su after reading /etc/shadow
RUN echo "root:exploitme123" | chpasswd

RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/yelp" > /etc/sudoers.d/yelp && \
    chmod 440 /etc/sudoers.d/yelp

RUN visudo -c

RUN chmod u+s /usr/bin/sudo

# Install su so we can switch users, and ensure it has proper perms
RUN chmod u+s /bin/su 2>/dev/null; chmod u+s /usr/bin/su 2>/dev/null; true

RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
