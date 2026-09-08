FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_pry
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/pry as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and pry (Ruby interactive shell)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        ruby \
        pry \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# pry might be installed as a gem rather than a system package
# If the apt package doesn't provide /usr/bin/pry, install via gem
RUN if ! which pry; then \
        apt-get update && \
        apt-get install -y ruby-dev build-essential && \
        gem install pry --no-document && \
        rm -rf /var/lib/apt/lists/*; \
    fi

# Create a wrapper script at /usr/bin/pry if it's installed elsewhere
RUN if [ ! -f /usr/bin/pry ]; then \
        PRY_PATH=$(which pry) && \
        ln -sf "$PRY_PATH" /usr/bin/pry; \
    fi

# Verify pry is installed and accessible
RUN ls -la /usr/bin/pry && /usr/bin/pry --version

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# pry is an interactive Ruby shell. When run as root via sudo,
# the attacker can execute arbitrary Ruby code to get a root shell:
#   sudo pry
#   system("/bin/bash")
# Or directly: sudo pry -e 'system("/bin/bash")'
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/pry" > /etc/sudoers.d/pry && \
    chmod 440 /etc/sudoers.d/pry

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