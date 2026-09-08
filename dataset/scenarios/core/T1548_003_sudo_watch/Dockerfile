FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_watch
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/watch as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and procps (which provides watch)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        procps \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify watch is installed
RUN which watch && ls -la /usr/bin/watch

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# watch can execute arbitrary commands. When run as root via sudo:
#   sudo watch -x /bin/sh -c 'reset; exec /bin/sh 1>&0 2>&0'
# This spawns a root shell.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/watch" > /etc/sudoers.d/watch && \
    chmod 440 /etc/sudoers.d/watch

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