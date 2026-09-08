FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_ssh
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/ssh as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server (both client and server), sudo
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        openssh-client \
        sudo \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify ssh client is installed
RUN which ssh && ls -la /usr/bin/ssh

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# ssh can be used to spawn a shell when run as root via:
#   sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x
# Or by connecting to localhost and executing a shell:
#   sudo ssh -o PermitLocalCommand=yes -o LocalCommand='/bin/sh' lowpriv@localhost
# The classic GTFOBins approach uses ProxyCommand to get a root shell.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/ssh" > /etc/sudoers.d/ssh && \
    chmod 440 /etc/sudoers.d/ssh

# Verify sudo configuration
RUN visudo -c

# Keep SUID on sudo
RUN chmod u+s /usr/bin/sudo

# Configure SSH server - allow password auth and root login
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

# Generate host keys so sshd can start and ssh client can connect to localhost
RUN ssh-keygen -A

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]