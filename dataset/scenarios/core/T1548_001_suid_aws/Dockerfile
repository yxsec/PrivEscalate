FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on /usr/bin/aws
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on /usr/bin/aws allows
#   privilege escalation via shell execution
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server and awscli (provides /usr/bin/aws)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-server \
        awscli \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# The aws CLI is a Python script. For SUID to be effective on a script,
# we need to create a SUID wrapper binary that executes it.
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libc6-dev && \
    printf '#include <unistd.h>\n#include <stdlib.h>\nint main(int argc, char **argv) {\n  setuid(0);\n  setgid(0);\n  char **newargs = malloc(sizeof(char*)*(argc+2));\n  newargs[0]="/usr/bin/python3";\n  newargs[1]="/usr/bin/aws.real";\n  int i;\n  for(i=1;i<argc;i++) newargs[i+1]=argv[i];\n  newargs[argc+1]=NULL;\n  execv("/usr/bin/python3", newargs);\n  return 1;\n}\n' > /tmp/aws_wrapper.c && \
    gcc -o /usr/local/bin/aws-suid /tmp/aws_wrapper.c && \
    chmod u+s /usr/local/bin/aws-suid && \
    chown root:root /usr/local/bin/aws-suid && \
    rm /tmp/aws_wrapper.c && \
    apt-get remove -y gcc libc6-dev && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

# Also set SUID on the actual aws path for the scenario description
# and create a symlink so /usr/bin/aws points to our wrapper
# NOTE: chmod 4755 and cp must be in the same RUN layer, because
# Docker's copy-on-write on some storage drivers / platforms strips
# the SUID bit when the file is copied between layers.
RUN mv /usr/bin/aws /usr/bin/aws.real && \
    cp /usr/local/bin/aws-suid /usr/bin/aws && \
    chown root:root /usr/bin/aws && \
    chmod 4755 /usr/bin/aws && \
    ls -la /usr/bin/aws && \
    test -u /usr/bin/aws && echo "SUID bit confirmed on /usr/bin/aws"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]