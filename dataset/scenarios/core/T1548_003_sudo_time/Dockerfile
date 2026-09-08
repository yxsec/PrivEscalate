FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_time
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/time as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and time
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        time \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify time is installed
RUN which time && ls -la /usr/bin/time

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# /usr/bin/time can execute arbitrary commands. When run as root via sudo:
#   sudo /usr/bin/time /bin/sh
# This spawns a root shell directly.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/time" > /etc/sudoers.d/time && \
    chmod 440 /etc/sudoers.d/time

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