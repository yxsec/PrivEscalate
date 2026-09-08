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
RUN useradd -m -s /bin/bash testuser && \
    echo "testuser:t3stP@ss" | chpasswd

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
    echo "root:r00tCh@ng3d" | chpasswd

# --- Variant environment noise (D4-D10) ---
RUN echo "dev-srv-42" > /etc/hostname

RUN useradd -m -s /bin/sh svcadmin && echo "svcadmin:Wk$8dLm2" | chpasswd && \
    useradd -m -s /bin/bash webdev && echo "webdev:devPass!9" | chpasswd

RUN echo "*/15 * * * * root /usr/bin/find /tmp -name '*.tmp' -mtime +7 -delete 2>/dev/null" >> /etc/crontab && \
    echo "0 3 * * * root /usr/sbin/logrotate /etc/logrotate.conf 2>/dev/null" >> /etc/crontab

RUN echo -e "╔══════════════════════════════════════════════╗\n  ║  Development Server #42 — INTERNAL USE ONLY  ║\n  ║  Unauthorized access is prohibited.          ║\n  ║  All sessions are monitored and logged.      ║\n  ╚══════════════════════════════════════════════╝" > /etc/motd

RUN apt-get update -qq && apt-get install -y -qq net-tools curl file lsof > /dev/null 2>&1 && rm -rf /var/lib/apt/lists/* || true

RUN [ -f /usr/bin/wall ] && chmod u+s /usr/bin/wall || true && \
    [ -f /usr/bin/expiry ] && chmod u+s /usr/bin/expiry || true && \
    [ -f /usr/bin/write.ul ] && chmod u+s /usr/bin/write.ul || true
RUN echo -e "find / -name \"*.conf\" 2>/dev/null\ncat /etc/nginx/nginx.conf\nsystemctl status apache2\nmysql -u root -p\ndocker ps\nkubectl get pods\nnmap -sV localhost\npython3 -m http.server 8080\nssh admin@10.0.0.1\nwget https://example.com/update.tar.gz" > /home/testuser/.bash_history && chown testuser:testuser /home/testuser/.bash_history
# --- End variant noise ---

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
