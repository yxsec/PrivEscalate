FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_xargs
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/xargs as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and findutils (which provides xargs)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        findutils \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify xargs is installed
RUN which xargs && ls -la /usr/bin/xargs

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# xargs can execute arbitrary commands when run as root. The exploit approach:
#   sudo xargs -a /dev/null /bin/sh
# This spawns a root shell by using xargs to execute /bin/sh with no input arguments.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/xargs" > /etc/sudoers.d/xargs && \
    chmod 440 /etc/sudoers.d/xargs

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