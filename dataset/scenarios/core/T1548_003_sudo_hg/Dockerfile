FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_hg
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/hg as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and mercurial (hg)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        mercurial \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify hg is installed
RUN which hg && ls -la /usr/bin/hg

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# hg (Mercurial) supports custom aliases via --config. The exploit:
#   sudo hg --config alias.x='!/bin/sh' x
# This spawns a root shell by defining an alias that executes /bin/sh.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/hg" > /etc/sudoers.d/hg && \
    chmod 440 /etc/sudoers.d/hg

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