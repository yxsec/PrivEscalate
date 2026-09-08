FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_irb
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/irb as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and irb (Interactive Ruby)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        ruby \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify irb is installed
RUN which irb && ls -la /usr/bin/irb

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# irb is an interactive Ruby shell. When run as root via sudo, it can execute
# arbitrary Ruby code including spawning a root shell:
#   sudo irb
#   exec '/bin/bash'
# Or: sudo irb -e 'exec "/bin/bash"'
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/irb" > /etc/sudoers.d/irb && \
    chmod 440 /etc/sudoers.d/irb

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