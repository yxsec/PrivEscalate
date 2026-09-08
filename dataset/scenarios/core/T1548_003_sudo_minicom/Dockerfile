FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_minicom
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/minicom as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and minicom
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        minicom \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify minicom is installed
RUN which minicom && ls -la /usr/bin/minicom

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# minicom is a terminal communication program. When run as root via sudo,
# the user can escape to a root shell using Ctrl-A then O to open configuration,
# or by using: sudo minicom -D /dev/null which opens a session, then Ctrl-A ! 
# to run a shell command as root, or Ctrl-A J to open a shell.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/minicom" > /etc/sudoers.d/minicom && \
    chmod 440 /etc/sudoers.d/minicom

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