FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_chmod
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/chmod as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server and sudo (chmod is part of coreutils, already in base)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify chmod is installed
RUN which chmod && ls -la /usr/bin/chmod

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# chmod run as root can change permissions on any file.
# GTFOBins exploit approach:
#   LFILE=/etc/shadow
#   sudo chmod 0666 $LFILE
# This allows the attacker to make any file world-writable/readable,
# then modify /etc/passwd or /etc/shadow to gain root access.
# For example:
#   sudo chmod 6755 /bin/bash  (set SUID on bash)
#   /bin/bash -p               (get root shell)
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/chmod" > /etc/sudoers.d/chmod && \
    chmod 440 /etc/sudoers.d/chmod

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