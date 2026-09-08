FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_doas
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/doas as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and doas
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        doas \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify doas is installed
RUN which doas && ls -la /usr/bin/doas

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Configure doas to permit root actions (needed so doas itself works when invoked as root)
# This allows: sudo doas -u root /bin/sh
RUN echo "permit nopass root" > /etc/doas.conf && \
    chmod 400 /etc/doas.conf

# --- Configure sudo vulnerability ---
# Allow lowpriv to run doas as root without password.
# Exploit: sudo doas -u root /bin/sh
# Since sudo runs doas as root, and doas.conf permits root to do anything,
# doas will then execute /bin/sh as root.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/doas" > /etc/sudoers.d/doas && \
    chmod 440 /etc/sudoers.d/doas

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