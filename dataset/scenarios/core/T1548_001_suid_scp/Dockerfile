FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on scp
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on /usr/bin/scp allows
#   privilege escalation via shell escape
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, openssh-client (provides scp), and gcc for C wrapper
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-server \
        openssh-client \
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

# Inject vulnerability: set SUID bit on scp
RUN chmod u+s /usr/bin/scp

# Also create a small SUID helper that simulates what a real
# SUID-scp exploit chain would achieve. In older kernels / older
# openssh, scp -S kept euid=0 when spawning the ssh replacement.
# Modern openssh drops privs, so we provide an additional SUID
# binary that represents the exploitable path.
RUN echo '#include <stdio.h>\n#include <stdlib.h>\n#include <unistd.h>\nint main(int argc,char**argv){setuid(0);setgid(0);if(argc>1){execvp(argv[1],&argv[1]);}else{system("/bin/bash -p");}return 0;}' > /tmp/scp_helper.c && \
    gcc -o /usr/local/bin/scp_helper /tmp/scp_helper.c && \
    chown root:root /usr/local/bin/scp_helper && \
    chmod 4755 /usr/local/bin/scp_helper && \
    rm /tmp/scp_helper.c

# Verify vulnerability is in place
RUN ls -la /usr/bin/scp | grep -q "rws" && echo "SUID bit confirmed on scp"
RUN ls -la /usr/local/bin/scp_helper | grep -q "rws" && echo "SUID helper confirmed"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
