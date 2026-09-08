FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on setcap
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on setcap allows
#   privilege escalation. With SUID setcap, attacker can grant
#   cap_setuid+ep to any binary (e.g., python3), then use it
#   to call setuid(0) and spawn a root shell.
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, libcap2-bin (provides setcap/getcap), and python3
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        libcap2-bin \
        python3 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Inject vulnerability: set SUID bit on setcap
RUN chmod u+s /usr/sbin/setcap

# Verify vulnerability is in place
RUN ls -la /usr/sbin/setcap | grep -q "rws" && echo "SUID bit confirmed on setcap"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
