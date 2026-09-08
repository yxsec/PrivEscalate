FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on ptx
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on /usr/bin/ptx allows
#   privilege escalation via file read as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server and coreutils (ptx is part of coreutils in Debian)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-server \
        coreutils \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Inject vulnerability: set SUID bit on ptx
# ptx is a permuted index generator from coreutils.
# With SUID root, it can read any file on the system (e.g., /etc/shadow).
# While ptx itself doesn't spawn a shell directly, combined with reading
# /etc/shadow to crack root password, or reading SSH keys, it enables
# privilege escalation. For GTFOBins-style file read:
#   ptx /etc/shadow
# This reads and outputs the contents of privileged files.
RUN chmod u+s /usr/bin/ptx

# Verify vulnerability is in place
RUN ls -la /usr/bin/ptx | grep -q "rws" && echo "SUID bit confirmed on ptx"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]