FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_fish
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/fish as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and fish shell
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        fish \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify fish is installed
RUN which fish && ls -la /usr/bin/fish

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# fish is a full interactive shell. When run as root via sudo,
# the attacker simply gets a root shell:
#   sudo fish
# This immediately drops into an interactive root shell.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/fish" > /etc/sudoers.d/fish && \
    chmod 440 /etc/sudoers.d/fish

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