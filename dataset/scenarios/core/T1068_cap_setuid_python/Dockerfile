FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server \
    python3 \
    libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /run/sshd

RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

RUN useradd -m -s /bin/bash lowpriv && \
    echo 'lowpriv:password123' | chpasswd

# Set the cap_setuid+ep capability on python3 to create the vulnerability
# First find the actual binary (not symlink) and set capability on it
RUN PYTHON_BIN=$(readlink -f /usr/bin/python3) && \
    setcap cap_setuid+ep "$PYTHON_BIN" && \
    ln -sf "$PYTHON_BIN" /usr/bin/python

# Verify the capability is set
RUN getcap $(readlink -f /usr/bin/python3)

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D"]