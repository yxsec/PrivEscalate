FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on ncftp
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on /usr/bin/ncftp allows
#   privilege escalation via shell escape
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server and ncftp
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-server \
        ncftp \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Inject vulnerability: set SUID bit on ncftp
RUN chmod u+s /usr/bin/ncftp

# Verify vulnerability is in place
# ncftp may be a script or the SUID bit format may vary (e.g. "rwS" if no execute bit).
# Use a more robust check that looks for the setuid bit via stat.
RUN stat -c '%a' /usr/bin/ncftp | grep -q '^4' && echo "SUID bit confirmed on ncftp" || \
    (ls -la /usr/bin/ncftp && echo "SUID verification note: ensuring suid is set" && chmod u+sx /usr/bin/ncftp && ls -la /usr/bin/ncftp)

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]