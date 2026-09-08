FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_zless
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/zless as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and gzip (which provides zless)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        gzip \
        less \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify zless is installed
RUN which zless && ls -la /usr/bin/zless

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# zless uses less as its pager. When run as root via sudo, the user can
# invoke an interactive shell from within less by typing:
#   !/bin/bash
# This inherits the root privileges, giving a root shell.
# Exploit: sudo zless /etc/profile
# Then type: !/bin/sh
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/zless" > /etc/sudoers.d/zless && \
    chmod 440 /etc/sudoers.d/zless

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