FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_R
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/R as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and R
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        r-base-core \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify R is installed
RUN which R && ls -la /usr/bin/R

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# R can spawn a shell via: sudo R -e 'system("/bin/bash")'
# or interactively: sudo R then system("/bin/sh")
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/R" > /etc/sudoers.d/R && \
    chmod 440 /etc/sudoers.d/R

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