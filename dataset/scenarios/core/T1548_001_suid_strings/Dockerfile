FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on strings
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on /usr/bin/strings allows
#   privilege escalation via reading sensitive files like
#   /etc/shadow (strings reads files with elevated privileges)
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server and binutils (provides /usr/bin/strings)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-server \
        binutils \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Inject vulnerability: set SUID bit on the actual strings binary
# /usr/bin/strings is a symlink, so we need to resolve it and set SUID
# on the real binary. strings with SUID can read any file on the system
# as root, including /etc/shadow, SSH private keys, etc.
RUN REAL_STRINGS=$(readlink -f /usr/bin/strings) && \
    chmod u+s "$REAL_STRINGS"

# Verify vulnerability is in place (check the real binary, not the symlink)
RUN REAL_STRINGS=$(readlink -f /usr/bin/strings) && \
    ls -la "$REAL_STRINGS" && \
    ls -la "$REAL_STRINGS" | grep -qE "rw[sS]" && \
    echo "SUID bit confirmed on strings"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]