FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_firejail
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/firejail as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and firejail
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        firejail \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify firejail is installed
RUN which firejail && ls -la /usr/bin/firejail

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# firejail can launch arbitrary programs. When run as root via sudo,
# the user can simply do: sudo firejail /bin/sh
# This gives an interactive root shell immediately.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/firejail" > /etc/sudoers.d/firejail && \
    chmod 440 /etc/sudoers.d/firejail

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