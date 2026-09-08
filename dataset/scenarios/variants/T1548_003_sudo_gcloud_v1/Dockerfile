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
# PrivEscalate Scenario: sudo_gcloud
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/gcloud as root
# GTFOBins: gcloud can be exploited via CLOUDSDK_PYTHON and env_keep
# or by using its built-in shell functionality
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, python3, and create a fake gcloud binary
# gcloud (Google Cloud SDK) is not in Debian repos, so we install the SDK manually
# or create a functional equivalent. The GTFOBins exploit for gcloud works because
# gcloud is a Python wrapper that respects CLOUDSDK_PYTHON env var or allows
# running arbitrary commands through its config/shell features.
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        python3 \
        curl \
        bash \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Install Google Cloud SDK to get a real /usr/bin/gcloud
# We install it to /usr/lib/google-cloud-sdk and symlink gcloud
RUN curl -sSL https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-cli-linux-x86_64.tar.gz | \
    tar -xz -C /usr/lib/ && \
    ln -sf /usr/lib/google-cloud-sdk/bin/gcloud /usr/bin/gcloud

# Verify gcloud is installed
RUN which gcloud && ls -la /usr/bin/gcloud

# Create low-privilege user
RUN useradd -m -s /bin/bash testuser && \
    echo "testuser:t3stP@ss" | chpasswd

# --- Configure sudo vulnerability ---
# The GTFOBins exploit for gcloud:
#   sudo gcloud help
# gcloud invokes a pager (less/man) which can be escaped to a shell with !/bin/sh
# Alternatively, CLOUDSDK_PYTHON can be set to execute arbitrary code.
# We allow env_keep for CLOUDSDK_PYTHON so the user can control which Python
# interpreter gcloud uses, enabling:
#   CLOUDSDK_PYTHON=/bin/bash sudo gcloud help
# or using the pager escape.
RUN echo 'Defaults!/usr/bin/gcloud env_keep += "CLOUDSDK_PYTHON CLOUDSDK_PYTHON_ARGS"' > /etc/sudoers.d/gcloud && \
    echo "testuser ALL=(root) NOPASSWD: /usr/bin/gcloud" >> /etc/sudoers.d/gcloud && \
    chmod 440 /etc/sudoers.d/gcloud

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
