FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on wish (Tcl/Tk)
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on /usr/bin/wish allows
#   privilege escalation via Tcl exec to spawn root shell
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server and tk (provides wish)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        tk \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Inject vulnerability: set SUID bit on wish
# wish may be a symlink; find the actual binary and set SUID on it
RUN WISH_PATH=$(readlink -f /usr/bin/wish) && \
    chmod u+s "$WISH_PATH" && \
    echo "SUID set on $WISH_PATH"

# Also set SUID on the symlink target and ensure /usr/bin/wish is accessible
RUN ls -la /usr/bin/wish && \
    ls -la $(readlink -f /usr/bin/wish) | grep -q "rws" && \
    echo "SUID bit confirmed on wish"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]