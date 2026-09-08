FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_mv
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/mv as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server and sudo
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        coreutils \
        openssl \
        python3 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify mv is installed
RUN which mv && ls -la /usr/bin/mv

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/mv" > /etc/sudoers.d/mv && \
    chmod 440 /etc/sudoers.d/mv

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
