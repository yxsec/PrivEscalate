FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_poetry
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/poetry as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, python3, pip, and poetry
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        python3 \
        python3-pip \
        pipx \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Install poetry via pipx as root so it lands in a predictable location
# Then symlink to /usr/bin/poetry for the sudo rule
RUN PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/bin pipx install poetry && \
    ls -la /usr/bin/poetry

# Verify poetry is installed and working
RUN /usr/bin/poetry --version

# Create low-privilege user
RUN useradd -m -s /bin/bash testuser && \
    echo "testuser:t3stP@ss" | chpasswd

# --- Configure sudo vulnerability ---
# Poetry inherits the root shell environment. GTFOBins exploit:
#   sudo poetry self update  (or other subcommands that can spawn a shell)
# The key exploit is:
#   sudo /usr/bin/poetry run /bin/sh
# This runs /bin/sh as root through poetry's "run" subcommand.
RUN echo "testuser ALL=(root) NOPASSWD: /usr/bin/poetry" > /etc/sudoers.d/poetry && \
    chmod 440 /etc/sudoers.d/poetry

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