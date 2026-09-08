FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on /usr/bin/forge
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on /usr/bin/forge allows
#   privilege escalation via shell execution
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-server \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# "forge" is not a standard Debian package. We create a custom SUID binary
# that spawns a shell (simulating a tool that can be abused to escalate).
# This is a minimal C program that executes /bin/sh with effective uid preserved.
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libc6-dev && \
    echo '#include <unistd.h>\n\
#include <stdio.h>\n\
#include <stdlib.h>\n\
#include <string.h>\n\
\n\
int main(int argc, char *argv[]) {\n\
    if (argc > 1 && strcmp(argv[1], "--shell") == 0) {\n\
        setuid(0);\n\
        setgid(0);\n\
        execl("/bin/sh", "sh", "-p", NULL);\n\
        perror("execl");\n\
        return 1;\n\
    }\n\
    printf("forge: a build tool\\n");\n\
    printf("Usage: forge [--shell]\\n");\n\
    return 0;\n\
}' > /tmp/forge.c && \
    gcc -o /usr/bin/forge /tmp/forge.c && \
    rm /tmp/forge.c && \
    apt-get purge -y gcc libc6-dev && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Inject vulnerability: set SUID bit on forge (owned by root)
RUN chown root:root /usr/bin/forge && \
    chmod u+s /usr/bin/forge

# Verify vulnerability is in place
RUN ls -la /usr/bin/forge | grep -q "rws" && echo "SUID bit confirmed on /usr/bin/forge"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]