FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_task
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/task as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and taskwarrior
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        taskwarrior \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify task is installed
RUN which task && ls -la /usr/bin/task

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Pre-create .taskrc for root so taskwarrior doesn't prompt interactively
RUN echo 'data.location=~/.task' > /root/.taskrc && \
    mkdir -p /root/.task

# Also create for lowpriv user
RUN echo 'data.location=~/.task' > /home/lowpriv/.taskrc && \
    mkdir -p /home/lowpriv/.task && \
    chown -R lowpriv:lowpriv /home/lowpriv/.taskrc /home/lowpriv/.task

# --- Configure sudo vulnerability ---
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/task" > /etc/sudoers.d/task && \
    chmod 440 /etc/sudoers.d/task

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
