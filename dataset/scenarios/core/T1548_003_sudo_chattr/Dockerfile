FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        e2fsprogs \
        openssl \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

RUN which chattr && ls -la /usr/bin/chattr

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Configure sudo vulnerability: allow chattr AND cp as root
# chattr removes immutable bits, cp allows overwriting /etc/passwd
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/chattr, /usr/bin/cp" > /etc/sudoers.d/chattr && \
    chmod 440 /etc/sudoers.d/chattr

# Set immutable attribute on /etc/passwd to make chattr step necessary
# Note: chattr on ext attributes may not work in all container filesystems,
# but the sudo cp is the key exploit path

RUN visudo -c

RUN chmod u+s /usr/bin/sudo

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
