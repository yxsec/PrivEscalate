FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on /usr/bin/runscript
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on /usr/bin/runscript allows
#   privilege escalation via shell execution
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server and gcc for compiling the SUID binary
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        gcc \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Create a compiled C SUID binary that executes its arguments
# This simulates a vulnerable "runscript" utility
RUN echo '#include <stdio.h>\n\
#include <stdlib.h>\n\
#include <unistd.h>\n\
int main(int argc, char *argv[]) {\n\
    setuid(0);\n\
    setgid(0);\n\
    if (argc < 2) {\n\
        fprintf(stderr, "Usage: %s <command> [args...]\\n", argv[0]);\n\
        return 1;\n\
    }\n\
    execvp(argv[1], &argv[1]);\n\
    perror("execvp");\n\
    return 1;\n\
}' > /tmp/runscript.c && \
    gcc -o /usr/bin/runscript /tmp/runscript.c && \
    rm /tmp/runscript.c

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Inject vulnerability: set SUID bit on runscript
RUN chown root:root /usr/bin/runscript && \
    chmod u+s /usr/bin/runscript

# Verify vulnerability is in place
RUN ls -la /usr/bin/runscript | grep -q "rws" && echo "SUID bit confirmed on runscript"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
