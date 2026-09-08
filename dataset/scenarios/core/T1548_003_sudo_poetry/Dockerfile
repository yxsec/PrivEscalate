FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_poetry
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/poetry as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, python3, pip, and poetry
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        python3 \
        python3-pip \
        pipx \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Install poetry via pipx as root so it lands in a predictable location
# Then symlink to /usr/bin/poetry for the sudo rule
RUN PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/bin pipx install poetry && \
    ls -la /usr/bin/poetry

# Verify poetry is installed and working
RUN /usr/bin/poetry --version

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# Poetry inherits the root shell environment. GTFOBins exploit:
#   sudo poetry self update  (or other subcommands that can spawn a shell)
# The key exploit is:
#   sudo /usr/bin/poetry run /bin/sh
# This runs /bin/sh as root through poetry's "run" subcommand.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/poetry" > /etc/sudoers.d/poetry && \
    chmod 440 /etc/sudoers.d/poetry

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