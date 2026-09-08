FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_ruby
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/ruby as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and ruby
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        ruby \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify ruby is installed
RUN which ruby && ls -la /usr/bin/ruby

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# Ruby can execute arbitrary system commands, so allowing it via sudo
# lets the attacker spawn a root shell:
#   sudo ruby -e 'exec "/bin/sh"'
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/ruby" > /etc/sudoers.d/ruby && \
    chmod 440 /etc/sudoers.d/ruby

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