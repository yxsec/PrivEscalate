FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_strace
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/strace as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and strace
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        strace \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify strace is installed
RUN which strace && ls -la /usr/bin/strace

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# strace can be used to spawn a root shell:
#   sudo strace -o /dev/null /bin/sh
# This traces /bin/sh as root, giving the user an interactive root shell
# with strace output discarded to /dev/null.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/strace" > /etc/sudoers.d/strace && \
    chmod 440 /etc/sudoers.d/strace

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