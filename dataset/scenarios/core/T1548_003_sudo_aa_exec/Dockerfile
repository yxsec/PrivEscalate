FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_aa-exec
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/aa-exec as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and apparmor (which provides aa-exec)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        apparmor \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify aa-exec is installed
RUN which aa-exec && ls -la /usr/bin/aa-exec

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# aa-exec can execute arbitrary commands under a given AppArmor profile
# With sudo, this allows: sudo aa-exec /bin/sh -> root shell
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/aa-exec" > /etc/sudoers.d/aa-exec && \
    chmod 440 /etc/sudoers.d/aa-exec

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