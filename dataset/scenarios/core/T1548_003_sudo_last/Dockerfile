FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        util-linux \
        openssl \
        john \
        coreutils \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

RUN which last && ls -la $(which last)

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Set a simple crackable root password
RUN echo "root:root" | chpasswd

# Configure sudo vulnerability - last can be run as root
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/last" > /etc/sudoers.d/last && \
    chmod 440 /etc/sudoers.d/last

RUN visudo -c

RUN chmod u+s /usr/bin/sudo

# Also make su usable (ensure lowpriv can run su)
RUN chmod u+s /bin/su

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]