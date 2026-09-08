FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_grc
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/grc as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and grc
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        grc \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify grc is installed
RUN which grc && ls -la /usr/bin/grc

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# grc supports --pty which allocates a pseudo-terminal and runs the given command.
# When run as root via sudo, `grc --pty /bin/sh` spawns a root shell.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/grc" > /etc/sudoers.d/grc && \
    chmod 440 /etc/sudoers.d/grc

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