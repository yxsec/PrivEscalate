FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_su
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/su as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and ensure su is available
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        login \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify su is installed
RUN which su && ls -la /usr/bin/su

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# Allow lowpriv to run /usr/bin/su as root without password.
# Exploit: sudo su -c /bin/sh
# This gives an interactive root shell immediately.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/su" > /etc/sudoers.d/su-vuln && \
    chmod 440 /etc/sudoers.d/su-vuln

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