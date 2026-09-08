FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on gnuplot
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on gnuplot wrapper allows
#   privilege escalation via: gnuplot -e 'system("sh -p")'
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, gnuplot, and gcc for building wrapper
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        gnuplot \
        gcc \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash testuser && \
    echo "testuser:t3stP@ss" | chpasswd

# Inject vulnerability: create a SUID C wrapper for gnuplot
# Linux ignores SUID on scripts/symlinks, so we need a compiled binary
RUN GNUPLOT_REAL=$(readlink -f /usr/bin/gnuplot) && \
    echo '#include <unistd.h>\n#include <stdio.h>\nint main(int argc, char **argv) { setuid(0); setgid(0); argv[0] = "'"$GNUPLOT_REAL"'"; execv("'"$GNUPLOT_REAL"'", argv); perror("execv"); return 1; }' > /tmp/gnuplot_wrapper.c && \
    gcc -o /usr/local/bin/gnuplot-suid /tmp/gnuplot_wrapper.c && \
    chown root:root /usr/local/bin/gnuplot-suid && \
    chmod 4755 /usr/local/bin/gnuplot-suid && \
    rm -f /tmp/gnuplot_wrapper.c

# Verify vulnerability is in place
RUN ls -la /usr/local/bin/gnuplot-suid | grep -q "rws" && echo "SUID bit confirmed on gnuplot-suid wrapper"

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
