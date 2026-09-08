FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_sudo
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/sudo as root
# The user can run "sudo sudo /bin/sh" to get a root shell, because
# the sudoers rule allows running /usr/bin/sudo itself as root with
# NOPASSWD, which then allows arbitrary command execution.
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server and sudo
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify sudo is installed
RUN which sudo && ls -la /usr/bin/sudo

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# Allowing a user to run /usr/bin/sudo as root means they can chain:
#   sudo sudo /bin/sh
# The first sudo invocation is permitted by the sudoers rule (running /usr/bin/sudo as root).
# The second sudo now runs as root and can execute anything, giving a root shell.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/sudo" > /etc/sudoers.d/sudo-vuln && \
    chmod 440 /etc/sudoers.d/sudo-vuln

# Verify sudo configuration
RUN visudo -c

# Keep SUID on sudo (required for sudo to function)
RUN chmod u+s /usr/bin/sudo

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]