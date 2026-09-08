FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-server \
        coreutils \
        python3 \
        gcc \
        libc6-dev \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Inject vulnerability: set SUID bit on /usr/bin/fmt
RUN chmod u+s /usr/bin/fmt

# Compile a small SUID helper that runs a command as root
RUN printf '#include <stdio.h>\n#include <stdlib.h>\n#include <unistd.h>\nint main(int argc,char**argv){if(argc<2){return 1;}setuid(0);setgid(0);return system(argv[1]);}\n' > /tmp/run.c && \
    gcc -o /usr/local/bin/suid_run /tmp/run.c && \
    chmod u+s /usr/local/bin/suid_run && \
    chmod 4755 /usr/local/bin/suid_run && \
    rm /tmp/run.c

RUN ls -la /usr/bin/fmt | grep -q "rws" && echo "SUID bit confirmed on fmt"

RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
