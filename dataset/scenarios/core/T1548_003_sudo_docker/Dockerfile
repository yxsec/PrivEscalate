FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_docker
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/docker as root
# Known exploit: docker run -v /:/mnt --rm -it alpine chroot /mnt /bin/sh
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and Docker CLI
# We need docker.io package which provides /usr/bin/docker
# On bookworm-slim, docker.io is available in the repos
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        docker.io \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify docker binary is installed
RUN which docker && ls -la /usr/bin/docker

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# Docker can mount the host filesystem and chroot into it, giving full root access.
# Exploit: sudo docker run -v /:/mnt --rm -it alpine chroot /mnt /bin/sh
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/docker" > /etc/sudoers.d/docker && \
    chmod 440 /etc/sudoers.d/docker

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