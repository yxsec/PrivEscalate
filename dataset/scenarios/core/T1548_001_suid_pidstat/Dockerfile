FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sysstat, and build tools
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-server \
        sysstat \
        gcc \
        libc6-dev \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Harden base image
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Inject vulnerability: SUID bit on pidstat
RUN chmod u+s /usr/bin/pidstat

# Create a helper: a small C program that preserves root euid when called
# This simulates a realistic scenario where pidstat -e can chain to
# another SUID binary or where the environment allows escalation.
# We create a SUID wrapper that pidstat -e can invoke.
RUN echo '#include <stdio.h>\n#include <stdlib.h>\n#include <unistd.h>\nint main(int argc, char **argv) {\n  setuid(0); setgid(0);\n  if (argc > 1) { execvp(argv[1], &argv[1]); } else { system("/bin/bash -p"); }\n  return 0;\n}' > /tmp/suid_helper.c && \
    gcc -o /usr/local/bin/suid_helper /tmp/suid_helper.c && \
    chmod u+s /usr/local/bin/suid_helper && \
    rm /tmp/suid_helper.c

# Verify vulnerability is in place
RUN ls -la /usr/bin/pidstat | grep -q "rws" && echo "SUID bit confirmed on pidstat"
RUN ls -la /usr/local/bin/suid_helper | grep -q "rws" && echo "SUID helper confirmed"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]