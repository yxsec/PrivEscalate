FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_setarch
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/setarch as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and util-linux (which provides setarch)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        util-linux \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify setarch is installed
RUN which setarch && ls -la /usr/bin/setarch

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# setarch can execute arbitrary commands under a different architecture personality.
# Exploit: sudo setarch $(uname -m) /bin/sh
# This spawns a root shell because setarch runs the specified command.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/setarch" > /etc/sudoers.d/setarch && \
    chmod 440 /etc/sudoers.d/setarch

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