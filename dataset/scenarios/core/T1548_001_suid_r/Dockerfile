FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on R wrapper binary
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on a compiled R-wrapper that
#   preserves root privileges, allowing privilege escalation.
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, R, and gcc to compile wrapper
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        r-base-core \
        gcc \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Create a SUID C wrapper that sets real/effective uid to 0 then execs R
RUN echo '#include <unistd.h>\n\
#include <stdlib.h>\n\
int main(int argc, char **argv) {\n\
    setuid(0);\n\
    setgid(0);\n\
    if (argc > 1) {\n\
        execvp("/usr/bin/R", argv);\n\
    } else {\n\
        char *args[] = {"/usr/bin/R", "--no-save", NULL};\n\
        execvp("/usr/bin/R", args);\n\
    }\n\
    return 1;\n\
}' > /tmp/r_wrapper.c && \
    gcc -o /usr/local/bin/R-suid /tmp/r_wrapper.c && \
    chown root:root /usr/local/bin/R-suid && \
    chmod 4755 /usr/local/bin/R-suid && \
    rm /tmp/r_wrapper.c

# Verify vulnerability is in place
RUN ls -la /usr/local/bin/R-suid | grep -q "rws" && echo "SUID bit confirmed on R-suid wrapper"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
