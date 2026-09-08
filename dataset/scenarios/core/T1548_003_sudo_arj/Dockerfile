FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_arj
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/arj as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and arj
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        arj \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify arj is installed
RUN which arj && ls -la /usr/bin/arj

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# arj can archive and extract arbitrary files when run as root.
# Exploit approach:
#   sudo arj a /tmp/evil /etc/shadow   (archive sensitive file)
#   arj p /tmp/evil                     (print contents to stdout)
# This allows reading privileged files like /etc/shadow.
# Combined with write capabilities (extracting crafted archives over /etc/passwd
# or /etc/shadow), this leads to full root compromise.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/arj" > /etc/sudoers.d/arj && \
    chmod 440 /etc/sudoers.d/arj

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