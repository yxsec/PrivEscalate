FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_batcat
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/batcat as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and bat (provides batcat on Debian)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        bat \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify batcat is installed
RUN which batcat && ls -la /usr/bin/batcat

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# batcat is a cat clone with syntax highlighting. When run via sudo,
# GTFOBins documents that it can be used to read arbitrary files as root.
# The exploit approach:
#   sudo batcat /etc/shadow
# This reads privileged files. Additionally, batcat invokes a pager (less)
# by default, and from within the pager one can execute:
#   !/bin/sh
# to spawn a root shell.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/batcat" > /etc/sudoers.d/batcat && \
    chmod 440 /etc/sudoers.d/batcat

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