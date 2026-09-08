FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_sash
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/sash as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and sash (stand-alone shell)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        sash \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify sash is installed
RUN which sash && ls -la /usr/bin/sash

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# sash is a stand-alone shell with many built-in commands. When run as root
# via sudo, it provides an interactive root shell directly.
# Exploit: sudo sash
# Then at the sash prompt you have a root shell with built-in commands
# including -chown, -chmod, -cp, -mv, -exec, etc.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/sash" > /etc/sudoers.d/sash && \
    chmod 440 /etc/sudoers.d/sash

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