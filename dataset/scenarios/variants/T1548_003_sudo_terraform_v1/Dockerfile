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
# PrivEscalate Scenario: sudo_terraform
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/terraform as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and dependencies
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        wget \
        unzip \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Install terraform binary (specific version for reproducibility).
# Detect architecture at build-time so arm64 hosts (e.g. Apple Silicon) get the right binary.
RUN ARCH=$(uname -m) && \
    case "$ARCH" in \
        x86_64|amd64) TF_ARCH=amd64 ;; \
        aarch64|arm64) TF_ARCH=arm64 ;; \
        *) echo "unsupported arch: $ARCH"; exit 1 ;; \
    esac && \
    wget -q "https://releases.hashicorp.com/terraform/1.5.7/terraform_1.5.7_linux_${TF_ARCH}.zip" -O /tmp/terraform.zip && \
    unzip /tmp/terraform.zip -d /usr/bin/ && \
    chmod 755 /usr/bin/terraform && \
    rm /tmp/terraform.zip

# Verify terraform is installed
RUN which terraform && ls -la /usr/bin/terraform && terraform version

# Create low-privilege user
RUN useradd -m -s /bin/bash testuser && \
    echo "testuser:t3stP@ss" | chpasswd

# --- Configure sudo vulnerability ---
# terraform console allows reading arbitrary files via file() function:
#   sudo terraform console
#   file("/etc/shadow")
# Additionally, terraform can execute arbitrary commands through provisioners
# or by abusing the console's file() to read sensitive credentials.
RUN echo "testuser ALL=(root) NOPASSWD: /usr/bin/terraform" > /etc/sudoers.d/terraform && \
    chmod 440 /etc/sudoers.d/terraform

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
