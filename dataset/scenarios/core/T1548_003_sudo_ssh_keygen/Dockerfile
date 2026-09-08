FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_ssh-keygen
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/ssh-keygen as root
# GTFOBins: ssh-keygen can load shared libraries via -D flag
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, openssh-client (for ssh-keygen), and build tools
# The exploit requires compiling a shared library, so we need gcc and libc-dev
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        openssh-client \
        sudo \
        gcc \
        libc6-dev \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify ssh-keygen is installed
RUN which ssh-keygen && ls -la /usr/bin/ssh-keygen

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# ssh-keygen supports loading shared libraries via the -D flag (PKCS#11 provider).
# When run as root via sudo, an attacker can craft a malicious shared library
# that executes arbitrary code as root when loaded:
#   sudo ssh-keygen -D ./lib.so
# The library's C_GetFunctionList function is called, which can exec /bin/sh.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/ssh-keygen" > /etc/sudoers.d/ssh-keygen && \
    chmod 440 /etc/sudoers.d/ssh-keygen

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