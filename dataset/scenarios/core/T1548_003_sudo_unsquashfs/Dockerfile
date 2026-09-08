FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_unsquashfs
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/unsquashfs as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and squashfs-tools (provides unsquashfs)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        squashfs-tools \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify unsquashfs is installed
RUN which unsquashfs && ls -la /usr/bin/unsquashfs

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# unsquashfs can extract squashfs archives as root, allowing overwrite of
# arbitrary files on the filesystem. An attacker can craft a squashfs image
# containing e.g. /etc/passwd or /etc/shadow with a known root password,
# then extract it with sudo unsquashfs to overwrite system files and gain root.
# GTFOBins documents this approach:
#   mksquashfs /etc/shadow exploit.sqfs
#   sudo unsquashfs -f -d / exploit.sqfs
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/unsquashfs" > /etc/sudoers.d/unsquashfs && \
    chmod 440 /etc/sudoers.d/unsquashfs

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