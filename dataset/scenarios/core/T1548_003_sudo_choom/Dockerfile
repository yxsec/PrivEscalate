FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_choom
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/choom as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and util-linux (which provides choom)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        util-linux \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify choom is installed
RUN which choom && ls -la /usr/bin/choom

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# choom can execute arbitrary commands with -n 0 -- /bin/sh
# When run as root via sudo, this spawns a root shell.
# Exploit: sudo choom -n 0 -- /bin/sh
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/choom" > /etc/sudoers.d/choom && \
    chmod 440 /etc/sudoers.d/choom

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