FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on clamscan
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on /usr/bin/clamscan allows
#   privilege escalation via file read as root using:
#   touch x.yara
#   clamscan --no-summary -d x.yara -f /path/to/file 2>&1
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, clamav, python3 (for su automation), and john for hash cracking
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        clamav \
        sed \
        python3 \
        openssl \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Inject vulnerability: set SUID bit on clamscan
RUN chmod u+s /usr/bin/clamscan

# Set a known root password
RUN echo "root:aim8Du7h" | chpasswd

# Verify vulnerability is in place
RUN ls -la /usr/bin/clamscan | grep -q "rws" && echo "SUID bit confirmed on clamscan"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]