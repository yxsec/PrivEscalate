FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on xz
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on /usr/bin/xz allows
#   privilege escalation via reading sensitive files like
#   /etc/shadow: xz -c /etc/shadow | xz -d
#   Or combined with other techniques to get a root shell.
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, xz-utils, openssl, and expect (for su automation)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-server \
        xz-utils \
        openssl \
        coreutils \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Inject vulnerability: set SUID bit on xz
RUN chmod u+s /usr/bin/xz

# Verify vulnerability is in place
RUN ls -la /usr/bin/xz | grep -q "rws" && echo "SUID bit confirmed on xz"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
