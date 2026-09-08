FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        coreutils \
        openssl \
        python3 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

RUN which date && ls -la /usr/bin/date

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Set a known crackable root password
RUN echo "root:aim8Du7h" | chpasswd

# Configure sudo vulnerability: date can be run as root
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/date" > /etc/sudoers.d/date && \
    chmod 440 /etc/sudoers.d/date

RUN visudo -c

RUN chmod u+s /usr/bin/sudo

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
