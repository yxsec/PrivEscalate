FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_timeout
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/timeout as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and coreutils (which provides timeout)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        coreutils \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify timeout is installed
RUN which timeout && ls -la /usr/bin/timeout

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# timeout can be used to spawn a shell as root:
#   sudo timeout --foreground 0 /bin/sh
# or simply:
#   sudo timeout 0 /bin/sh
# When the duration is 0, timeout runs the command with no time limit,
# effectively giving an interactive root shell.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/timeout" > /etc/sudoers.d/timeout && \
    chmod 440 /etc/sudoers.d/timeout

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