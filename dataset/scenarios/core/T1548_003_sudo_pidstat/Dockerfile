FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_pidstat
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/pidstat as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and sysstat (which provides pidstat)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        sysstat \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify pidstat is installed
RUN which pidstat && ls -la /usr/bin/pidstat

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# pidstat has a -e option that executes an arbitrary command.
# When run via sudo: sudo pidstat -e /bin/sh
# This spawns a root shell.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/pidstat" > /etc/sudoers.d/pidstat && \
    chmod 440 /etc/sudoers.d/pidstat

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