FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_scanmem
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/scanmem as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and scanmem
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        scanmem \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify scanmem is installed
RUN which scanmem && ls -la $(which scanmem)

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# scanmem has an interactive shell command that allows executing arbitrary
# commands. When run as root via sudo, the user can type:
#   shell /bin/sh
# to get a root shell.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/scanmem" > /etc/sudoers.d/scanmem && \
    chmod 440 /etc/sudoers.d/scanmem

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