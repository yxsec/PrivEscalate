FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on /usr/bin/python3
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on /usr/bin/python3 allows
#   privilege escalation via: python3 -c 'import os; os.execl("/bin/sh", "sh", "-p")'
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server and Python3
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        python3 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Create /usr/bin/python symlink pointing to python3 (matching the scenario description)
RUN ln -sf /usr/bin/python3 /usr/bin/python

# Inject vulnerability: set SUID bit on the actual python3 binary (not the symlink)
# We need to set SUID on the real binary that python3 points to
RUN chmod u+s $(readlink -f /usr/bin/python3)

# Verify vulnerability is in place
RUN ls -la $(readlink -f /usr/bin/python3) | grep -q "rws" && echo "SUID bit confirmed on python3"
RUN ls -la /usr/bin/python3

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]