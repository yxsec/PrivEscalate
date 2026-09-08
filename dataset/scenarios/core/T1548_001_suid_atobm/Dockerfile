FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on atobm
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on /usr/bin/atobm allows
#   privilege escalation via shell escape
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server and x11-apps (provides atobm)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-server \
        x11-apps \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Install python3 for exploit chain
RUN apt-get update && \
    apt-get install -y --no-install-recommends python3 && \
    rm -rf /var/lib/apt/lists/*

# Inject vulnerability: set SUID bit on atobm
RUN chmod u+s /usr/bin/atobm

# Create a SUID copy of bash for escalation path
# cp may not preserve ownership, and the SUID bit pattern depends on
# whether the file is owned by root. Also, for a non-root-owned file
# the SUID bit shows as 'S' (uppercase) vs 's' (lowercase) depending
# on whether execute is also set. We ensure proper ownership and permissions.
RUN cp /bin/bash /usr/local/bin/rootbash && \
    chown root:root /usr/local/bin/rootbash && \
    chmod 4755 /usr/local/bin/rootbash

# Verify vulnerability is in place
RUN ls -la /usr/bin/atobm | grep -q "rws" && echo "SUID bit confirmed on atobm"
RUN ls -la /usr/local/bin/rootbash && \
    ls -la /usr/local/bin/rootbash | grep -q "rwsr" && echo "SUID rootbash confirmed"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]