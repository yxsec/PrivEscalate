FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_uv
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/uv as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and dependencies for uv
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Install uv (the Python package manager / runner) via official installer
# uv is a single static binary, installed to /usr/local/bin by default
RUN curl -LsSf https://astral.sh/uv/install.sh | sh && \
    cp /root/.local/bin/uv /usr/bin/uv && \
    chmod 755 /usr/bin/uv

# Verify uv is installed
RUN which uv && ls -la /usr/bin/uv && uv --version

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# uv can run arbitrary commands via "uv run <command>", so allowing it
# via sudo gives the user a direct path to root shell:
#   sudo uv run /bin/sh
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/uv" > /etc/sudoers.d/uv && \
    chmod 440 /etc/sudoers.d/uv

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