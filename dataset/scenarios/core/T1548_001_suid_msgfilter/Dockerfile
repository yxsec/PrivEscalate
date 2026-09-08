FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on msgfilter
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on /usr/bin/msgfilter allows
#   privilege escalation via shell execution
# Exploit: echo x | msgfilter -P /bin/sh -p -c '/bin/sh -p 0<&2 1>&2; kill $PPID'
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server and gettext (provides msgfilter)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-server \
        gettext \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Inject vulnerability: set SUID bit on msgfilter
RUN chmod u+s /usr/bin/msgfilter

# Verify vulnerability is in place
RUN ls -la /usr/bin/msgfilter | grep -q "rws" && echo "SUID bit confirmed on msgfilter"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]