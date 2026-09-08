FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_rlwrap
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/rlwrap as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and rlwrap
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        rlwrap \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify rlwrap is installed
RUN which rlwrap && ls -la /usr/bin/rlwrap

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# rlwrap wraps any command with readline support. When run as root via sudo,
# it can wrap /bin/sh to give an interactive root shell:
#   sudo rlwrap /bin/sh
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/rlwrap" > /etc/sudoers.d/rlwrap && \
    chmod 440 /etc/sudoers.d/rlwrap

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