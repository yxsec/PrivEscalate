FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_wish
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/wish as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and wish (Tcl/Tk)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        tk \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify wish is installed
RUN which wish && ls -la /usr/bin/wish*

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# wish is a Tcl/Tk interpreter. When run as root via sudo, it can execute
# arbitrary commands. The GTFOBins exploit approach:
#   sudo wish -exec 'exec /bin/sh <@stdin >@stdout 2>@stderr'
# This spawns a root shell.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/wish" > /etc/sudoers.d/wish && \
    chmod 440 /etc/sudoers.d/wish

# Also allow the versioned symlink target
RUN WISH_REAL=$(readlink -f /usr/bin/wish) && \
    echo "lowpriv ALL=(root) NOPASSWD: $WISH_REAL" >> /etc/sudoers.d/wish && \
    chmod 440 /etc/sudoers.d/wish

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