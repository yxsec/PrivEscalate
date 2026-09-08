FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_dash
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/dash as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and dash
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        dash \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify dash is installed
RUN which dash && ls -la /usr/bin/dash

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# dash is a shell, so running it as root via sudo immediately gives a root shell:
#   sudo dash
# This drops the user into an interactive root shell with uid=0.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/dash" > /etc/sudoers.d/dash && \
    chmod 440 /etc/sudoers.d/dash

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