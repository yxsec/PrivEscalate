FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_busybox
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/busybox as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and busybox
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        busybox \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify busybox is installed
RUN which busybox && ls -la /usr/bin/busybox

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# busybox contains a full shell (sh) and many utilities. The exploit:
#   sudo busybox sh
# This spawns a root shell directly. It can also be used for reverse shells,
# file uploads/downloads, and arbitrary file read/write as root.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/busybox" > /etc/sudoers.d/busybox && \
    chmod 440 /etc/sudoers.d/busybox

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