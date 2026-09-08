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
# PrivEscalate Scenario: SUID on /bin/su (CVE-2000-0844 style)
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on /bin/su allows privilege
#   escalation. While CVE-2000-0844 was a glibc format string
#   bug in locale handling affecting SUID /bin/su on old systems,
#   we simulate the core attack surface: SUID /bin/su combined
#   with a known root password enabling direct escalation.
#   The attacker uses: /bin/su -c 'id' root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, build tools, and utilities the exploit references
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        login \
        util-linux \
        gcc \
        binutils \
        gettext \
        locales \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Generate some locales (exploit uses LC_MESSAGES manipulation)
RUN sed -i 's/^# *en_US.UTF-8/en_US.UTF-8/' /etc/locale.gen && \
    locale-gen

# Create low-privilege user
RUN useradd -m -s /bin/bash testuser && \
    echo "testuser:t3stP@ss" | chpasswd

# Inject vulnerability: Ensure SUID bit is set on /bin/su
# On modern Debian, su is in /bin/su (or /usr/bin/su via symlink)
# We ensure SUID is explicitly set, which is the core attack surface
RUN chmod u+s /bin/su 2>/dev/null || chmod u+s /usr/bin/su 2>/dev/null

# Set a weak/known root password that the testuser user can exploit via SUID su
RUN echo "root:r00tCh@ng3d" | chpasswd

# Place the exploit source in the testuser user's home for reference
RUN echo '#!/bin/sh\n# CVE-2000-0844 style escalation via SUID /bin/su\n# With known root password, SUID su grants root shell:\nexec /bin/su -c "/bin/sh" root' > /home/testuser/exploit.sh && \
    chmod +x /home/testuser/exploit.sh && \
    chown testuser:testuser /home/testuser/exploit.sh

# Verify vulnerability is in place
RUN ls -la /bin/su | grep -q "rws" && echo "SUID bit confirmed on /bin/su" || \
    (ls -la /usr/bin/su | grep -q "rws" && echo "SUID bit confirmed on /usr/bin/su")

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

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
