FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_vi
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/vi as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and vi (vim-tiny is default in bookworm-slim but install explicitly)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        vim \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify vi is installed
RUN which vi && ls -la /usr/bin/vi

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# vi can spawn a shell via :!/bin/sh when run as root.
# Exploit: sudo vi -c ':!/bin/sh' /dev/null
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/vi" > /etc/sudoers.d/vi && \
    chmod 440 /etc/sudoers.d/vi

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