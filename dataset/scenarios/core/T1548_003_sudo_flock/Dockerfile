FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_flock
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/flock as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and util-linux (which provides flock)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        util-linux \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify flock is installed
RUN which flock && ls -la /usr/bin/flock

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# flock can execute arbitrary commands while holding a lock.
# Exploit: sudo flock -u / /bin/sh
# This spawns a root shell via flock's command execution capability.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/flock" > /etc/sudoers.d/flock && \
    chmod 440 /etc/sudoers.d/flock

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