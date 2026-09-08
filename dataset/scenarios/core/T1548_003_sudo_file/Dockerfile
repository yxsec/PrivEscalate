FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_file
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/file as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and file utility
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        file \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify file is installed
RUN which file && ls -la /usr/bin/file

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# The `file` command supports -f flag to read a list of filenames from a file.
# When run as root via sudo, this can be abused to read arbitrary files:
#   sudo file -f /etc/shadow
# The file command will try to interpret each line as a filename and print
# error messages containing the line content, effectively leaking file contents.
# This enables reading /etc/shadow, SSH keys, and other sensitive files,
# which can lead to full root compromise (e.g., cracking root password hash
# or reading root's private SSH key).
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/file" > /etc/sudoers.d/file && \
    chmod 440 /etc/sudoers.d/file

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