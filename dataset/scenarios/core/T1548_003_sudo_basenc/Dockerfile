FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_basenc
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/basenc as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, coreutils (basenc), and openssl for password hashing
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        coreutils \
        openssl \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify basenc is installed
RUN which basenc && ls -la /usr/bin/basenc

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/basenc" > /etc/sudoers.d/basenc && \
    chmod 440 /etc/sudoers.d/basenc

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
