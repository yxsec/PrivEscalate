FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_softlimit
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/softlimit as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and daemontools (provides softlimit)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        daemontools \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify softlimit is installed
RUN which softlimit && ls -la $(which softlimit)

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# softlimit sets resource limits and then executes a given command.
# When run as root via sudo, it can execute arbitrary commands as root:
#   sudo softlimit /bin/sh
# This gives an interactive root shell.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/softlimit" > /etc/sudoers.d/softlimit && \
    chmod 440 /etc/sudoers.d/softlimit

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