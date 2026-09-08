FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server and required packages
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-server \
        iftop \
        gcc \
        libc6-dev \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Inject vulnerability: set SUID bit on iftop
RUN chmod u+s /usr/sbin/iftop && \
    ln -sf /usr/sbin/iftop /usr/bin/iftop

# Create a SUID wrapper that leverages the concept of SUID iftop
# In reality, iftop doesn't have a shell escape, so we simulate
# the scenario with a helper: iftop_wrapper that execs a shell as root
RUN echo '#include <stdio.h>\n#include <stdlib.h>\n#include <unistd.h>\nint main(int argc, char **argv) {\n  setuid(0); setgid(0);\n  if (argc > 1) { execvp(argv[1], &argv[1]); }\n  else { char *args[] = {"/bin/sh", "-p", NULL}; execv("/bin/sh", args); }\n  return 1;\n}' > /tmp/iftop_escalate.c && \
    gcc -o /usr/local/bin/iftop_escalate /tmp/iftop_escalate.c && \
    chmod u+s /usr/local/bin/iftop_escalate && \
    rm /tmp/iftop_escalate.c

# Verify vulnerability is in place
RUN ls -la /usr/sbin/iftop | grep -q "rws" && echo "SUID bit confirmed on iftop"
RUN ls -la /usr/local/bin/iftop_escalate | grep -q "rws" && echo "SUID bit confirmed on iftop_escalate"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]