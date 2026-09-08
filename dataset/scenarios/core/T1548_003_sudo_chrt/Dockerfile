FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_chrt
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/chrt as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and util-linux (which provides chrt)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        util-linux \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify chrt is installed
RUN which chrt && ls -la /usr/bin/chrt

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# chrt sets scheduling policy/priority and then executes a command.
# When run as root via sudo, it can execute arbitrary commands as root:
#   sudo chrt 1 /bin/sh
# This spawns a root shell.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/chrt" > /etc/sudoers.d/chrt && \
    chmod 440 /etc/sudoers.d/chrt

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