FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_tmate
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/tmate as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and tmate
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        tmate \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify tmate is installed
RUN which tmate && ls -la /usr/bin/tmate

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# tmate can launch a new terminal session. When run as root via sudo,
# the exploit is: sudo tmate -c /bin/sh
# The -c flag tells tmate to run a command, which gives a root shell.
# Alternatively: sudo tmate new-session -d && sudo tmate send-keys '/bin/sh' Enter
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/tmate" > /etc/sudoers.d/tmate && \
    chmod 440 /etc/sudoers.d/tmate

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