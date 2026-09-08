FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on csh
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on /usr/bin/csh allows
#   privilege escalation via: csh -b then running commands as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server and csh
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-server \
        csh \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Inject vulnerability: set SUID bit on /usr/bin/csh
# Note: /usr/bin/csh may be a symlink; we need to set SUID on the actual binary
RUN if [ -L /usr/bin/csh ]; then \
        TARGET=$(readlink -f /usr/bin/csh) && \
        chmod u+s "$TARGET"; \
    else \
        chmod u+s /usr/bin/csh; \
    fi

# Verify vulnerability is in place (check both the symlink target and csh itself)
RUN ls -la /usr/bin/csh && \
    ls -la $(readlink -f /usr/bin/csh) && \
    stat -c '%A' $(readlink -f /usr/bin/csh) | grep -q 's' && echo "SUID bit confirmed on csh"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]