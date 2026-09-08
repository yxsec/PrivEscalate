FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_aria2c
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/aria2c as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and aria2
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        aria2 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify aria2c is installed
RUN which aria2c && ls -la /usr/bin/aria2c

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# aria2c supports --on-download-error which executes an arbitrary command
# when a download fails. An attacker can:
#   1. Create a script that spawns a root shell or modifies /etc/passwd
#   2. Run: sudo aria2c --on-download-error=/tmp/exploit http://x
#   3. The download to an invalid URL fails, triggering the script as root
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/aria2c" > /etc/sudoers.d/aria2c && \
    chmod 440 /etc/sudoers.d/aria2c

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