FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on /usr/bin/rpm
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on /usr/bin/rpm allows
#   privilege escalation via: rpm --eval '%{lua:os.execute("/bin/sh -p")}'
# ============================================================
# NOTE: rpm is not in default Debian bookworm-slim but is available
# as a package in Debian repos (the `rpm` package).
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server and rpm
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        rpm \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Inject vulnerability: set SUID bit on rpm
RUN chmod u+s /usr/bin/rpm

# Verify vulnerability is in place
RUN ls -la /usr/bin/rpm | grep -q "rws" && echo "SUID bit confirmed on rpm"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]