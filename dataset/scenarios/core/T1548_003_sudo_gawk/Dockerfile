FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_gawk
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/gawk as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and gawk
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        gawk \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify gawk is installed
RUN which gawk && ls -la /usr/bin/gawk

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# gawk can spawn a shell via: sudo gawk 'BEGIN {system("/bin/sh")}'
# This gives the attacker an interactive root shell immediately.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/gawk" > /etc/sudoers.d/gawk && \
    chmod 440 /etc/sudoers.d/gawk

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