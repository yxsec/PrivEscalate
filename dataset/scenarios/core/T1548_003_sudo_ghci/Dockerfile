FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_ghci
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/ghci as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and GHC (which includes ghci)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        ghc \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify ghci is installed
RUN which ghci && ls -la /usr/bin/ghci

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# ghci is the GHC interactive Haskell interpreter. When run as root via sudo,
# an attacker can execute arbitrary system commands:
#   sudo ghci
#   System.Process.callCommand "/bin/sh"
# This spawns a root shell.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/ghci" > /etc/sudoers.d/ghci && \
    chmod 440 /etc/sudoers.d/ghci

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