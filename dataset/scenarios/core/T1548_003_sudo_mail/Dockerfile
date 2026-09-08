FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_mail
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/mail as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and mailutils (provides /usr/bin/mail)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        mailutils \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify mail is installed
RUN which mail && ls -la $(which mail)

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# mail allows executing shell commands via --exec='!/bin/sh' or
# interactively with ~! escape. When run as root via sudo, this
# grants a root shell.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/mail" > /etc/sudoers.d/mail && \
    chmod 440 /etc/sudoers.d/mail

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