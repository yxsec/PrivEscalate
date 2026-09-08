FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_gdb
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/gdb as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and gdb
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        gdb \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify gdb is installed
RUN which gdb && ls -la /usr/bin/gdb

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# gdb can execute shell commands via -ex '!/bin/sh'
# Exploit: sudo gdb -nx -ex '!/bin/sh' -ex quit
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/gdb" > /etc/sudoers.d/gdb && \
    chmod 440 /etc/sudoers.d/gdb

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