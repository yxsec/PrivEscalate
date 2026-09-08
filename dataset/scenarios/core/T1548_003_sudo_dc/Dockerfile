FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_dc
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/dc as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and dc (part of bc package in Debian)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        dc \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify dc is installed
RUN which dc && ls -la /usr/bin/dc

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# dc supports the ! command to execute shell commands.
# Exploit: sudo dc -e '!/bin/sh'
# This spawns a root shell immediately.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/dc" > /etc/sudoers.d/dc && \
    chmod 440 /etc/sudoers.d/dc

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