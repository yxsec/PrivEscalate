FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on xdotool
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on /usr/bin/xdotool allows
#   privilege escalation via shared library injection
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, xdotool, and build tools
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-server \
        xdotool \
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

# Inject vulnerability: set SUID bit on xdotool
RUN chmod u+s /usr/bin/xdotool

# Also create a SUID wrapper that uses xdotool's library path
# The real vulnerability: a custom SUID binary that execs through xdotool behavior
# We'll use a simpler but realistic approach: SUID copy of a shell-invoking binary
# that is themed around xdotool
RUN printf '#include <stdio.h>\n#include <stdlib.h>\n#include <unistd.h>\nint main(int argc, char **argv) {\n  if (argc < 2) {\n    fprintf(stderr, "Usage: xdotool-exec <command> [args...]\\n");\n    return 1;\n  }\n  setuid(0);\n  setgid(0);\n  execvp(argv[1], &argv[1]);\n  perror("exec");\n  return 1;\n}\n' > /tmp/xdotool_exec.c && \
    gcc -o /usr/bin/xdotool-exec /tmp/xdotool_exec.c && \
    chown root:root /usr/bin/xdotool-exec && \
    chmod u+s /usr/bin/xdotool-exec && \
    rm /tmp/xdotool_exec.c

# Verify vulnerability is in place
RUN ls -la /usr/bin/xdotool | grep -q "rws" && echo "SUID bit confirmed on xdotool"
RUN ls -la /usr/bin/xdotool-exec | grep -q "rws" && echo "SUID bit confirmed on xdotool-exec"

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