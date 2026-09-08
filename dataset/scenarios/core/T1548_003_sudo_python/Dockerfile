FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_python
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/python as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and python3
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        python3 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Create a symlink so /usr/bin/python exists (Debian bookworm uses python3)
RUN ln -sf /usr/bin/python3 /usr/bin/python

# Verify python is installed and accessible
RUN which python && python --version
RUN ls -la /usr/bin/python

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# Allow lowpriv to run /usr/bin/python as root without password.
# Exploit: sudo python -c 'import os; os.execl("/bin/sh", "sh")'
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/python" > /etc/sudoers.d/python && \
    chmod 440 /etc/sudoers.d/python

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