FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_octave
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/octave-cli as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and octave
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        octave \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify octave-cli is installed
RUN which octave-cli && ls -la /usr/bin/octave-cli

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# octave-cli can execute system commands when run as root. The exploit approach:
#   sudo octave-cli --eval 'system("/bin/sh")'
# This spawns a root shell via Octave's system() function.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/octave-cli" > /etc/sudoers.d/octave && \
    chmod 440 /etc/sudoers.d/octave

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