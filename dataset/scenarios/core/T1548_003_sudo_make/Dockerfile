FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_make
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/make as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and make
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        make \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify make is installed
RUN which make && ls -la /usr/bin/make

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# make can execute arbitrary shell commands via --eval, enabling root shell:
#   sudo make --eval='$(shell /bin/sh 1>&0)' .
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/make" > /etc/sudoers.d/make && \
    chmod 440 /etc/sudoers.d/make

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