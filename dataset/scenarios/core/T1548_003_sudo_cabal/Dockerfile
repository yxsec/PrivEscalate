FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_cabal
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/cabal as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and cabal-install
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        cabal-install \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify cabal is installed
RUN which cabal && ls -la /usr/bin/cabal

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# cabal exec can be used to execute arbitrary commands as root:
#   sudo cabal exec --project-file=/dev/null -- /bin/sh
# This spawns a root shell directly.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/cabal" > /etc/sudoers.d/cabal && \
    chmod 440 /etc/sudoers.d/cabal

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