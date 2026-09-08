FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on ar
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on /usr/bin/ar allows
#   privilege escalation via file read/write as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server and binutils (provides ar)
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

# Inject vulnerability: set SUID bit on ar
RUN chmod u+s /usr/bin/ar

# Verify vulnerability is in place
# The default permissions for ar are 755, so with SUID it becomes 4755.
# stat -c '%a' returns the octal mode which could be 4755 (4 digits) or
# sometimes represented differently. Use a more robust check.
RUN perl -e 'my $mode = (stat("/usr/bin/ar"))[2]; exit(($mode & 04000) ? 0 : 1)' && echo "SUID bit confirmed on ar"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]