FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_lp
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/lp as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, cups-client, and expect for su automation
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        cups-client \
        expect \
        openssl \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify lp is installed
RUN which lp && ls -la /usr/bin/lp

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# Allow lowpriv to run lp as root without password
# Also allow running tee as root (simulating a broader misconfiguration
# where the admin also granted tee for "printing to file" workflows)
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/lp" > /etc/sudoers.d/lp && \
    echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/tee" >> /etc/sudoers.d/lp && \
    chmod 440 /etc/sudoers.d/lp

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
