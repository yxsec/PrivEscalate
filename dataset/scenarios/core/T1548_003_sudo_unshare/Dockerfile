FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_unshare
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/unshare as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and util-linux (provides unshare)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        util-linux \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify unshare is installed
RUN which unshare && ls -la /usr/bin/unshare

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# unshare can create new namespaces and execute arbitrary commands.
# When run as root via sudo, the attacker can simply do:
#   sudo unshare /bin/sh
# This spawns a root shell immediately.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/unshare" > /etc/sudoers.d/unshare && \
    chmod 440 /etc/sudoers.d/unshare

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