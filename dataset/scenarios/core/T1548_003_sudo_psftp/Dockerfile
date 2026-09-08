FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_psftp
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/psftp as root
# psftp has an interactive shell where you can run !/bin/sh to get a root shell
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and putty-tools (which provides psftp)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        putty-tools \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify psftp is installed
RUN which psftp && ls -la /usr/bin/psftp

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# psftp is an interactive SFTP client. From its prompt, a user can execute
# local shell commands using the ! prefix, e.g.:
#   psftp> !/bin/sh
# When run via sudo as root, this spawns a root shell.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/psftp" > /etc/sudoers.d/psftp && \
    chmod 440 /etc/sudoers.d/psftp

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