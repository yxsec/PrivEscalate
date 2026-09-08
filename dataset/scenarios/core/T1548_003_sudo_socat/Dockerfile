FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_socat
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/socat as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and socat
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        socat \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify socat is installed
RUN which socat && ls -la /usr/bin/socat

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# socat can spawn an interactive shell when run as root:
#   sudo socat stdin exec:/bin/sh,pty,stderr,setsid,sigint,sane
# This gives the attacker a root shell directly.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/socat" > /etc/sudoers.d/socat && \
    chmod 440 /etc/sudoers.d/socat

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