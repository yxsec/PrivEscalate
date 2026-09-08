FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server \
    tcl \
    tcl-dev \
    gcc \
    libc6-dev \
    libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /run/sshd

RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

RUN useradd -m -s /bin/bash lowpriv && \
    echo 'lowpriv:password123' | chpasswd

# /usr/bin/tclsh is a symlink; setcap requires a regular file.
# Resolve the symlink and set the capability on the actual binary.
RUN TCLSH_REAL=$(readlink -f /usr/bin/tclsh) && \
    setcap cap_setuid+ep "$TCLSH_REAL"

# Verify the capability is set
RUN getcap $(readlink -f /usr/bin/tclsh)

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D"]
