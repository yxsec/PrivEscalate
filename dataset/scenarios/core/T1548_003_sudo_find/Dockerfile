FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_find
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/find as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and findutils (find)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        findutils \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify find is installed
RUN which find && ls -la /usr/bin/find

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# find can execute arbitrary commands via -exec. The exploit approach:
#   sudo find . -exec /bin/sh \; -quit
# This spawns a root shell immediately.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/find" > /etc/sudoers.d/find && \
    chmod 440 /etc/sudoers.d/find

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