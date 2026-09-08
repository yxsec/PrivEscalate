FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on tclsh
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on /usr/bin/tclsh allows
#   privilege escalation via: tclsh exec /bin/sh -p
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server and tcl (provides tclsh)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-server \
        tcl \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Inject vulnerability: set SUID bit on tclsh
# tclsh is typically a symlink; we need to set SUID on the actual binary
# First find the real binary, then set SUID on both the symlink target and ensure the link works
RUN TCLSH_REAL=$(readlink -f /usr/bin/tclsh) && \
    chmod u+s "$TCLSH_REAL" && \
    echo "SUID set on $TCLSH_REAL"

# Verify vulnerability is in place
RUN TCLSH_REAL=$(readlink -f /usr/bin/tclsh) && \
    ls -la "$TCLSH_REAL" | grep -q "rws" && echo "SUID bit confirmed on tclsh"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]