FROM debian:bookworm-slim

# Install required packages
RUN apt-get update && apt-get install -y \
    openssh-server \
    gcc \
    libc6-dev \
    coreutils \
    passwd \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Setup SSH
RUN mkdir -p /var/run/sshd && \
    sed -i 's/#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config

# Create low-privilege user
RUN useradd -m -s /bin/bash testuser && \
    echo 'testuser:t3stP@ss' | chpasswd

# Create the surun binary that runs /tmp/NetClient/client as root
RUN printf '%s\n' \
    '#include <stdio.h>' \
    '#include <stdlib.h>' \
    '#include <unistd.h>' \
    '#include <sys/types.h>' \
    '#include <sys/stat.h>' \
    '' \
    '#define CLIENT_PATH "/tmp/NetClient/client"' \
    '' \
    'int main(int argc, char *argv[]) {' \
    '    struct stat st;' \
    '    if (stat(CLIENT_PATH, &st) != 0) {' \
    '        fprintf(stderr, "Error: client not found at %s\\n", CLIENT_PATH);' \
    '        return 1;' \
    '    }' \
    '    setuid(0);' \
    '    setgid(0);' \
    '    execl(CLIENT_PATH, "client", NULL);' \
    '    perror("execl failed");' \
    '    return 1;' \
    '}' > /tmp/surun.c

RUN gcc -o /usr/local/bin/surun /tmp/surun.c && \
    chown root:root /usr/local/bin/surun && \
    chmod 4755 /usr/local/bin/surun && \
    rm /tmp/surun.c

# Create the /tmp/NetClient directory with insecure permissions
RUN mkdir -p /tmp/NetClient && \
    chmod 777 /tmp/NetClient

# Create the original "client" binary - world-writable (the vulnerability)
RUN printf '#!/bin/sh\necho "Nortel VPN Client running"\n' > /tmp/NetClient/client && \
    chmod a+xw /tmp/NetClient/client

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