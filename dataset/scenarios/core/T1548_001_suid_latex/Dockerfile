FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, texlive, and build tools
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        texlive-latex-base \
        gcc \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Inject vulnerability: set SUID bit on latex
RUN LATEX_PATH=$(readlink -f /usr/bin/latex) && \
    chmod u+s "$LATEX_PATH" && \
    echo "SUID set on $LATEX_PATH"

# Also create a small SUID root helper that latex's write18 can call
# This simulates the real-world scenario where SUID pdftex can be leveraged
# We create a SUID copy of a shell-invoking binary
RUN printf '#include <unistd.h>\n#include <stdlib.h>\nint main(int argc, char **argv){setuid(0);setgid(0);if(argc>2)execvp(argv[1],argv+1);else system(argv[1]);return 0;}\n' > /tmp/suidhelper.c && \
    gcc -o /usr/local/bin/suidhelper /tmp/suidhelper.c && \
    chmod 4755 /usr/local/bin/suidhelper && \
    rm /tmp/suidhelper.c

# Verify vulnerability is in place
RUN ls -la $(readlink -f /usr/bin/latex) | grep -q "rws" && echo "SUID bit confirmed on latex"
RUN ls -la /usr/local/bin/suidhelper | grep -q "rws" && echo "SUID helper confirmed"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]