FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on uuencode
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on /usr/bin/uuencode allows
#   privilege escalation via file read as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server and sharutils (provides uuencode)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-server \
        sharutils \
        openssl \
        coreutils \
        python3 \
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

# Inject vulnerability: set SUID bit on uuencode
RUN chmod u+s /usr/bin/uuencode

# Also set SUID on a helper to allow writing files as root
RUN echo '#include <stdio.h>' > /tmp/rootcp.c && \
    echo '#include <stdlib.h>' >> /tmp/rootcp.c && \
    echo '#include <unistd.h>' >> /tmp/rootcp.c && \
    echo 'int main(int argc, char **argv) {' >> /tmp/rootcp.c && \
    echo '  setuid(0); setgid(0);' >> /tmp/rootcp.c && \
    echo '  if(argc==3) {' >> /tmp/rootcp.c && \
    echo '    char cmd[4096];' >> /tmp/rootcp.c && \
    echo '    snprintf(cmd,sizeof(cmd),"cp %s %s",argv[1],argv[2]);' >> /tmp/rootcp.c && \
    echo '    return system(cmd);' >> /tmp/rootcp.c && \
    echo '  }' >> /tmp/rootcp.c && \
    echo '  return 1;' >> /tmp/rootcp.c && \
    echo '}' >> /tmp/rootcp.c && \
    gcc -o /usr/local/bin/rootcp /tmp/rootcp.c && \
    chmod u+s /usr/local/bin/rootcp && \
    rm /tmp/rootcp.c

# Verify vulnerability is in place
RUN ls -la /usr/bin/uuencode | grep -q "rws" && echo "SUID bit confirmed on uuencode"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
