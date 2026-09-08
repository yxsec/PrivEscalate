FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on /usr/bin/vim
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on vim allows
#   privilege escalation via: vim -c ':py3 import os; os.execl("/bin/sh", "sh", "-p")'
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server and vim-nox (full version with Python3 support)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        vim-nox \
        python3 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Inject vulnerability: set SUID bit on the actual vim binary
# vim-nox installs vim.nox as the binary
RUN VIMBIN=$(readlink -f /usr/bin/vim) && \
    chmod u+s "$VIMBIN" && \
    echo "SUID bit set on $VIMBIN"

# Verify vulnerability is in place
RUN VIMBIN=$(readlink -f /usr/bin/vim) && \
    ls -la "$VIMBIN" | grep -q "rws" && echo "SUID bit confirmed on $VIMBIN"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
