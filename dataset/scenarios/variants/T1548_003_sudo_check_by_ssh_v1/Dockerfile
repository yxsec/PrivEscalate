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
# PrivEscalate Scenario: sudo_check_by_ssh
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/check_by_ssh as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and monitoring-plugins (which provides check_by_ssh)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        monitoring-plugins-basic \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# check_by_ssh is part of monitoring-plugins-basic and typically installed to
# /usr/lib/nagios/plugins/check_by_ssh. Create a symlink to /usr/bin/ for
# consistency with the scenario description.
RUN if [ -f /usr/lib/nagios/plugins/check_by_ssh ]; then \
        ln -sf /usr/lib/nagios/plugins/check_by_ssh /usr/bin/check_by_ssh; \
    fi

# Verify check_by_ssh is available
RUN ls -la /usr/bin/check_by_ssh && /usr/bin/check_by_ssh --help || true

# Create low-privilege user
RUN useradd -m -s /bin/bash testuser && \
    echo "testuser:t3stP@ss" | chpasswd

# --- Configure sudo vulnerability ---
# check_by_ssh allows executing arbitrary commands on a remote host via SSH.
# When run as root via sudo, an attacker can use it to connect back to localhost
# (or the same host) and execute arbitrary commands as root.
# Exploit approach:
#   1. Generate SSH key for root or use existing connectivity
#   2. sudo check_by_ssh -H 127.0.0.1 -C '/bin/bash -i' 
#   Or more directly, check_by_ssh has a -C option that specifies the command
#   to run on the remote host. If the attacker sets up SSH keys or uses the
#   local host, they can get a root shell.
#   Simplest: sudo check_by_ssh -H 127.0.0.1 -l root -C 'cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash'
RUN echo "testuser ALL=(root) NOPASSWD: /usr/bin/check_by_ssh" > /etc/sudoers.d/check_by_ssh && \
    chmod 440 /etc/sudoers.d/check_by_ssh

# Set up root SSH key so check_by_ssh can connect to localhost as root
RUN ssh-keygen -t ed25519 -f /root/.ssh/id_ed25519 -N "" -q && \
    cat /root/.ssh/id_ed25519.pub >> /root/.ssh/authorized_keys && \
    chmod 600 /root/.ssh/authorized_keys

# Pre-accept localhost host key to avoid interactive prompt
RUN mkdir -p /etc/ssh && \
    ssh-keygen -A && \
    ssh-keyscan -H 127.0.0.1 >> /root/.ssh/known_hosts 2>/dev/null; \
    ssh-keyscan -H localhost >> /root/.ssh/known_hosts 2>/dev/null; \
    true

# Verify sudo configuration
RUN visudo -c

# Keep SUID on sudo
RUN chmod u+s /usr/bin/sudo

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
