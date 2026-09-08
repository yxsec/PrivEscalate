FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_sqlite3
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/sqlite3 as root
# Known exploit: sudo sqlite3 /dev/null '.shell /bin/sh'
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and sqlite3
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        sqlite3 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify sqlite3 is installed
RUN which sqlite3 && ls -la /usr/bin/sqlite3

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# sqlite3 has a .shell command that spawns a shell.
# When run as root via sudo, this gives a root shell:
#   sudo sqlite3 /dev/null '.shell /bin/sh'
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/sqlite3" > /etc/sudoers.d/sqlite3 && \
    chmod 440 /etc/sudoers.d/sqlite3

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