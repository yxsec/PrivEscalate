FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on head
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on /usr/bin/head allows
#   privilege escalation via reading sensitive files (e.g.,
#   /etc/shadow) to crack root password or read SSH keys
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, coreutils (provides head), john for cracking, and util-linux for su
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-server \
        coreutils \
        openssl \
        john \
        util-linux \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Inject vulnerability: set SUID bit on head
RUN chmod u+s /usr/bin/head

# Verify vulnerability is in place
RUN ls -la /usr/bin/head | grep -q "rws" && echo "SUID bit confirmed on head"

# Configure SSH - use a weak root password that can be cracked
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]