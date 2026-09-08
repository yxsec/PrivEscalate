FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    openssh-server \
    gdb \
    sudo \
    procps \
    ncurses-bin \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /run/sshd

RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

RUN useradd -m -s /bin/bash lowpriv && \
    echo 'lowpriv:password123' | chpasswd

# Grant lowpriv passwordless sudo (the misconfiguration that enables the exploit)
RUN echo 'lowpriv ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/lowpriv && \
    chmod 440 /etc/sudoers.d/lowpriv

# Ensure ptrace_scope will be 0 at runtime
RUN echo '#!/bin/bash' > /start.sh && \
    echo 'echo 0 > /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || true' >> /start.sh && \
    echo 'exec /usr/sbin/sshd -D' >> /start.sh && \
    chmod +x /start.sh

RUN chown lowpriv:lowpriv /home/lowpriv/

# Verify gdb is installed and sudo is configured
RUN which gdb && sudo -l -U lowpriv

EXPOSE 22

CMD ["/start.sh"]