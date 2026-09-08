FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_ssh-agent
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/ssh-agent as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and openssh-client (which provides ssh-agent)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        openssh-client \
        sudo \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify ssh-agent is installed
RUN which ssh-agent && ls -la /usr/bin/ssh-agent

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# ssh-agent can execute an arbitrary command via:
#   sudo ssh-agent /bin/bash
# This spawns a root shell because ssh-agent runs the specified command
# as a subprocess, inheriting the root privileges from sudo.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/ssh-agent" > /etc/sudoers.d/ssh-agent && \
    chmod 440 /etc/sudoers.d/ssh-agent

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