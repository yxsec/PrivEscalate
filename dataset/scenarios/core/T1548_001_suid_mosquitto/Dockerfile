FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-server \
        mosquitto \
        mosquitto-clients \
        openssl \
        coreutils \
        gcc \
        libc6-dev \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Create a SUID wrapper that mimics the mosquitto escalation path.
# When invoked with --escalate, it gives a root shell.
# This simulates a vulnerable SUID mosquitto binary that can be abused.
RUN echo '#include <stdio.h>\n#include <stdlib.h>\n#include <unistd.h>\n#include <string.h>\nint main(int argc, char **argv) {\n  if (argc > 1 && strcmp(argv[1], "--exec") == 0 && argc > 2) {\n    setuid(0); setgid(0);\n    execvp(argv[2], &argv[2]);\n    perror("exec");\n    return 1;\n  }\n  /* normal mosquitto behavior placeholder */\n  return 0;\n}' > /tmp/suid_mosquitto.c && \
    gcc -o /usr/local/bin/mosquitto_suid /tmp/suid_mosquitto.c && \
    chown root:root /usr/local/bin/mosquitto_suid && \
    chmod u+s /usr/local/bin/mosquitto_suid && \
    rm /tmp/suid_mosquitto.c

# Also set SUID on the real mosquitto for appearance
RUN chown root:root /usr/sbin/mosquitto && \
    chmod u+s /usr/sbin/mosquitto

RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
