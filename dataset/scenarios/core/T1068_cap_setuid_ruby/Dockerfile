FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server \
    ruby \
    libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /run/sshd

RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

RUN useradd -m -s /bin/bash lowpriv && \
    echo 'lowpriv:password123' | chpasswd

# /usr/bin/ruby is a symlink; resolve it and set the capability on the actual binary
RUN RUBY_REAL=$(readlink -f /usr/bin/ruby) && \
    setcap cap_setuid+ep "$RUBY_REAL"

# Verify the capability is set
RUN getcap $(readlink -f /usr/bin/ruby)

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D"]