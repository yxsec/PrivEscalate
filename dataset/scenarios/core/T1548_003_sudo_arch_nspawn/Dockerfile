FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_arch-nspawn
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/arch-nspawn as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and required packages
# arch-nspawn doesn't exist as a Debian package - it's an Arch Linux tool.
# We'll create a script that mimics arch-nspawn's behavior (spawning a shell
# in a namespace context) since the real tool is Arch-specific.
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        systemd-container \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Create a simulated arch-nspawn binary that behaves like the real one.
# The real arch-nspawn from Arch Linux is a bash script that uses systemd-nspawn
# to spawn into a container/chroot. It accepts a root directory and then
# arbitrary commands to run. This allows command execution as root when
# run via sudo.
RUN printf '#!/bin/bash\n\
# arch-nspawn - simplified version mimicking Arch Linux devtools arch-nspawn\n\
# Usage: arch-nspawn <root-dir> [command...]\n\
if [ $# -lt 1 ]; then\n\
    echo "Usage: arch-nspawn <root-dir> [command...]" >&2\n\
    exit 1\n\
fi\n\
CHROOT="$1"\n\
shift\n\
if [ $# -eq 0 ]; then\n\
    exec /bin/bash\n\
else\n\
    exec "$@"\n\
fi\n' > /usr/bin/arch-nspawn && \
    chmod 755 /usr/bin/arch-nspawn

# Verify arch-nspawn is installed
RUN which arch-nspawn && ls -la /usr/bin/arch-nspawn

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# arch-nspawn can execute arbitrary commands when given a root directory
# With sudo: sudo arch-nspawn /tmp /bin/sh -> root shell
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/arch-nspawn" > /etc/sudoers.d/arch-nspawn && \
    chmod 440 /etc/sudoers.d/arch-nspawn

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