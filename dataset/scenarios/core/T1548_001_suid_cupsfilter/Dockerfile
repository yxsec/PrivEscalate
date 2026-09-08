FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-server \
        cups \
        cups-filters \
        cups-client \
        gcc \
        libc6-dev \
        coreutils \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Set SUID on the actual cupsfilter binary
RUN chmod u+s /usr/sbin/cupsfilter && \
    ls -la /usr/sbin/cupsfilter

# Also create a SUID C wrapper that execs cupsfilter preserving euid
RUN echo '#include <unistd.h>\nint main(int argc, char **argv) { setuid(0); setgid(0); execv("/usr/sbin/cupsfilter", argv); return 1; }' > /tmp/wrap.c && \
    gcc -o /usr/local/bin/cupsfilter-suid /tmp/wrap.c && \
    chmod u+s /usr/local/bin/cupsfilter-suid && \
    rm /tmp/wrap.c

# Make /etc/passwd world-writable so cupsfilter running as root can write to it
# (simulating a misconfiguration that pairs with the SUID binary)
RUN chmod 0666 /etc/passwd

RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]