FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_rpmdb
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/rpmdb as root
# Known exploit: rpmdb --eval '%(/bin/sh 1>&2)'
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and rpm (which provides rpmdb on Debian)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        rpm \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify rpmdb is installed
# On Debian, rpm package provides /usr/bin/rpmdb
RUN which rpmdb && ls -la $(which rpmdb)

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# rpmdb (and rpm tools) support --eval with macro expansion.
# The %() macro executes shell commands, so:
#   sudo rpmdb --eval '%(/bin/sh 1>&2)'
# spawns a root shell.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/rpmdb" > /etc/sudoers.d/rpmdb && \
    chmod 440 /etc/sudoers.d/rpmdb

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