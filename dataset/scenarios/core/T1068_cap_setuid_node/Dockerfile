FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server \
    nodejs \
    libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /run/sshd

RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

RUN useradd -m -s /bin/bash lowpriv && \
    echo 'lowpriv:password123' | chpasswd

# Set the cap_setuid+ep capability on node to create the vulnerability
RUN setcap cap_setuid+ep /usr/bin/node

# Verify the capability is set
RUN getcap /usr/bin/node

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D"]