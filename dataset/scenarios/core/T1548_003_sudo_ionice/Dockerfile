FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_ionice
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/ionice as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and ionice (part of util-linux)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        util-linux \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify ionice is installed
RUN which ionice && ls -la /usr/bin/ionice

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# ionice can execute arbitrary commands with the specified I/O scheduling class.
# Exploit: sudo ionice /bin/sh
# This spawns a root shell because ionice runs the given command as a child process.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/ionice" > /etc/sudoers.d/ionice && \
    chmod 440 /etc/sudoers.d/ionice

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