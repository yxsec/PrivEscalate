FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_elvish
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/elvish as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and elvish
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        elvish \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify elvish is installed
RUN which elvish && ls -la /usr/bin/elvish

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# elvish is a shell, so running it as root via sudo gives an interactive root shell.
# Exploit: sudo elvish
# This drops the user into a root shell immediately.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/elvish" > /etc/sudoers.d/elvish && \
    chmod 440 /etc/sudoers.d/elvish

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