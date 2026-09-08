FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_ptx
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/ptx as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and coreutils (ptx is part of coreutils)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        coreutils \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify ptx is installed
RUN which ptx && ls -la /usr/bin/ptx

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# ptx can be abused to read arbitrary files when run as root.
# The exploit approach: sudo ptx -w 5000 /etc/shadow
# This outputs the contents of privileged files in a permuted index format,
# leaking sensitive data like password hashes. Combined with reading
# /etc/shadow or SSH private keys, this leads to full root compromise.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/ptx" > /etc/sudoers.d/ptx && \
    chmod 440 /etc/sudoers.d/ptx

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