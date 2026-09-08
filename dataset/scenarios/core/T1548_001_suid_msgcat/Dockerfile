FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on msgcat
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on /usr/bin/msgcat allows
#   privilege escalation via file-read: msgcat treats files as PO catalogs
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, gettext (provides msgcat), and utilities needed for exploit
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-server \
        gettext \
        openssl \
        expect \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Set a known root password so the exploit can su after reading shadow
RUN echo "root:aim8Du7h" | chpasswd

# Inject vulnerability: set SUID bit on msgcat
RUN chmod u+s /usr/bin/msgcat

# Verify vulnerability is in place
RUN ls -la /usr/bin/msgcat | grep -q "rws" && echo "SUID bit confirmed on msgcat"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]