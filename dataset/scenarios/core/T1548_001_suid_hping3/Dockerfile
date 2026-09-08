FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on hping3
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on /usr/bin/hping3 allows
#   privilege escalation via: hping3 -> /bin/sh -p
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server and hping3
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        hping3 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Inject vulnerability: set SUID bit on hping3
RUN chmod u+s /usr/sbin/hping3 && \
    ln -sf /usr/sbin/hping3 /usr/bin/hping3

# Verify vulnerability is in place
RUN ls -la /usr/sbin/hping3 | grep -q "rws" && echo "SUID bit confirmed on hping3"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]