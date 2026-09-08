FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_env
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/env as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server and sudo
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify env is installed
RUN which env && ls -la /usr/bin/env

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# env can be used to spawn an arbitrary command as root:
#   sudo env /bin/sh
# This gives an immediate root shell.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/env" > /etc/sudoers.d/env && \
    chmod 440 /etc/sudoers.d/env

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