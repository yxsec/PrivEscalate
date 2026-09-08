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
# PrivEscalate Scenario: SUID on simulated cdda2cdr binary
# ATT&CK: T1548.001 | CVE-2000-0362
# Vulnerability: SUID root bit set on /usr/bin/cdda2cdr
#   simulating the cwdtools vulnerability from SuSE 6.1/6.2
#   where cdda2cdr was SUID root, allowing privilege escalation.
#   Modern reproduction: SUID binary that spawns a shell.
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, gcc for compilation, and basic tools
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        gcc \
        libc6-dev \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Create a simulated vulnerable cdda2cdr SUID binary using printf
RUN printf '#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n#include <unistd.h>\nint main(int argc, char *argv[]) {\n  int i;\n  for (i = 1; i < argc; i++) {\n    if (strcmp(argv[i], "-e") == 0 && i + 1 < argc) {\n      setuid(0); setgid(0);\n      execl("/bin/sh", "sh", "-c", argv[i+1], NULL);\n      perror("execl"); return 1;\n    }\n  }\n  fprintf(stderr, "cdda2cdr (cwdtools) - CD writing utility\\n");\n  return 0;\n}\n' > /tmp/cdda2cdr.c && \
    gcc -o /usr/bin/cdda2cdr /tmp/cdda2cdr.c && \
    rm -f /tmp/cdda2cdr.c

# Inject vulnerability: set SUID root bit on cdda2cdr (mimicking SuSE 6.x default)
# chown first, then chmod, because chown can reset the SUID bit
RUN chown root:root /usr/bin/cdda2cdr && \
    chmod u+s /usr/bin/cdda2cdr

# Verify vulnerability is in place
RUN ls -la /usr/bin/cdda2cdr && ls -la /usr/bin/cdda2cdr | grep -q "rws" && echo "SUID bit confirmed on cdda2cdr"

# Create low-privilege user
RUN useradd -m -s /bin/bash testuser && \
    echo "testuser:t3stP@ss" | chpasswd

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
