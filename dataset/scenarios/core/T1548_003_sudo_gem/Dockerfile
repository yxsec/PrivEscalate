FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_gem
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/gem as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and ruby/gem
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        ruby \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify gem is installed
RUN which gem && ls -la /usr/bin/gem

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# gem open -e '/bin/sh -s' debug allows spawning a root shell
# The `gem open` command opens a gem's source in an editor. By setting the
# editor to '/bin/sh -s', it spawns a shell instead. 'debug' is a gem that
# is typically available by default with Ruby.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/gem" > /etc/sudoers.d/gem && \
    chmod 440 /etc/sudoers.d/gem

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