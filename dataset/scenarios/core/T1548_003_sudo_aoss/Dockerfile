FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_aoss
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/aoss as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and alsa-oss (which provides aoss)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        alsa-oss \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify aoss is installed
RUN which aoss && ls -la /usr/bin/aoss

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# aoss is a wrapper script that executes an arbitrary command with ALSA OSS emulation
# With sudo, this allows: sudo aoss /bin/sh -> root shell
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/aoss" > /etc/sudoers.d/aoss && \
    chmod 440 /etc/sudoers.d/aoss

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