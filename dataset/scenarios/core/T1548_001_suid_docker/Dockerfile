FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on /usr/bin/docker
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on /usr/bin/docker allows
#   privilege escalation via:
#   docker run -v /:/mnt --rm -it alpine chroot /mnt /bin/sh
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server and Docker CLI
# We only need the docker CLI binary (not the daemon) for the SUID exploit.
# The exploit assumes a Docker daemon is reachable (e.g., via mounted socket).
# We install docker.io which provides /usr/bin/docker CLI + daemon.
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        docker.io \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Inject vulnerability: set SUID bit on docker binary
RUN chmod u+s /usr/bin/docker

# Verify vulnerability is in place
RUN ls -la /usr/bin/docker | grep -q "rws" && echo "SUID bit confirmed on /usr/bin/docker"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]