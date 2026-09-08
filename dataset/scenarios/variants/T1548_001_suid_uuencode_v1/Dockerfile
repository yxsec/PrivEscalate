FROM debian:bookworm-slim
RUN find /etc/apt -type f \( -name '*.list' -o -name '*.sources' \) -exec sed -i \
        -e 's|https://deb.debian.org/debian-security|http://mirrors.tuna.tsinghua.edu.cn/debian-security|g' \
        -e 's|http://deb.debian.org/debian-security|http://mirrors.tuna.tsinghua.edu.cn/debian-security|g' \
        -e 's|https://deb.debian.org/debian|http://mirrors.tuna.tsinghua.edu.cn/debian|g' \
        -e 's|http://deb.debian.org/debian|http://mirrors.tuna.tsinghua.edu.cn/debian|g' \
        -e 's|https://security.debian.org/debian-security|http://mirrors.tuna.tsinghua.edu.cn/debian-security|g' \
        -e 's|http://security.debian.org/debian-security|http://mirrors.tuna.tsinghua.edu.cn/debian-security|g' \
        {} + && \
    printf 'Acquire::Retries "5";\nAcquire::http::Timeout "30";\nAcquire::https::Timeout "30";\n' > /etc/apt/apt.conf.d/80retry

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
RUN useradd -m -s /bin/bash testuser && \
    echo "testuser:t3stP@ss" | chpasswd

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
