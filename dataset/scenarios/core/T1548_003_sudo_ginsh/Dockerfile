FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_ginsh
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/ginsh as root
# ginsh is an interactive GiNaC shell that supports ! to execute shell commands
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and ginac-tools (provides ginsh)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        ginac-tools \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify ginsh is installed
RUN which ginsh && ls -la /usr/bin/ginsh

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# ginsh supports the ! prefix to execute shell commands.
# Running `sudo ginsh` then typing `!/bin/sh` gives a root shell.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/ginsh" > /etc/sudoers.d/ginsh && \
    chmod 440 /etc/sudoers.d/ginsh

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