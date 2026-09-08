FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on custom binary
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on a custom binary that allows
#   privilege escalation
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server and required packages
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        file \
        gcc \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash testuser && \
    echo "testuser:t3stP@ss" | chpasswd

# Inject vulnerability: set SUID bit on /usr/bin/file
RUN chmod u+s /usr/bin/file

# Also create a SUID helper that can be discovered and abused.
# This simulates a realistic scenario where an admin created a
# SUID wrapper that invokes 'file' but can be abused via PATH manipulation.
RUN echo '#include <stdio.h>\n#include <stdlib.h>\n#include <unistd.h>\nint main(int argc, char **argv) {\n  setuid(0);\n  setgid(0);\n  if (argc > 1) {\n    system(argv[1]);\n  } else {\n    system("/usr/bin/file --version");\n  }\n  return 0;\n}' > /tmp/filehelper.c && \
    gcc -o /usr/local/bin/filehelper /tmp/filehelper.c && \
    chown root:root /usr/local/bin/filehelper && \
    chmod u+s /usr/local/bin/filehelper && \
    rm /tmp/filehelper.c

# Verify vulnerability is in place
RUN ls -la /usr/bin/file | grep -q "rws" && echo "SUID bit confirmed on /usr/bin/file"
RUN ls -la /usr/local/bin/filehelper | grep -q "rws" && echo "SUID bit confirmed on /usr/local/bin/filehelper"

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
