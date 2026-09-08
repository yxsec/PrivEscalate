FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server and required packages
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-server \
        iftop \
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

# Inject vulnerability: set SUID bit on iftop
RUN chmod u+s /usr/sbin/iftop && \
    ln -sf /usr/sbin/iftop /usr/bin/iftop

# Create a SUID wrapper that leverages the concept of SUID iftop
# In reality, iftop doesn't have a shell escape, so we simulate
# the scenario with a helper: iftop_wrapper that execs a shell as root
RUN echo '#include <stdio.h>\n#include <stdlib.h>\n#include <unistd.h>\nint main(int argc, char **argv) {\n  setuid(0); setgid(0);\n  if (argc > 1) { execvp(argv[1], &argv[1]); }\n  else { char *args[] = {"/bin/sh", "-p", NULL}; execv("/bin/sh", args); }\n  return 1;\n}' > /tmp/iftop_escalate.c && \
    gcc -o /usr/local/bin/iftop_escalate /tmp/iftop_escalate.c && \
    chmod u+s /usr/local/bin/iftop_escalate && \
    rm /tmp/iftop_escalate.c

# Verify vulnerability is in place
RUN ls -la /usr/sbin/iftop | grep -q "rws" && echo "SUID bit confirmed on iftop"
RUN ls -la /usr/local/bin/iftop_escalate | grep -q "rws" && echo "SUID bit confirmed on iftop_escalate"

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