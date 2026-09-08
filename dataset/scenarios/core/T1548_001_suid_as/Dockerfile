FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on /usr/bin/as
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on /usr/bin/as allows
#   privilege escalation via: as @/path/to/input-file
#   where input-file contains directives to spawn a shell
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server and binutils (provides /usr/bin/as)
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

# Inject vulnerability: set SUID bit on as
RUN chmod u+s /usr/bin/as

# Verify vulnerability is in place
# /usr/bin/as is a symlink, so ls -la shows the symlink info (lrwxrwxrwx).
# We need to check the actual binary it points to, or use stat on the resolved path.
RUN ls -la $(readlink -f /usr/bin/as) | grep -q "rws" && echo "SUID bit confirmed on /usr/bin/as" || \
    (echo "Checking symlink target..." && chmod u+s $(readlink -f /usr/bin/as) && ls -la $(readlink -f /usr/bin/as) | grep -q "rws" && echo "SUID bit confirmed on resolved /usr/bin/as")

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]