FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_multitime
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/multitime as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and multitime
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        multitime \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify multitime is installed
RUN which multitime && ls -la /usr/bin/multitime

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# multitime is designed to run arbitrary commands and time them.
# When allowed via sudo with NOPASSWD, the attacker can simply run:
#   sudo multitime -n 1 /bin/sh
# This spawns an interactive root shell.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/multitime" > /etc/sudoers.d/multitime && \
    chmod 440 /etc/sudoers.d/multitime

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