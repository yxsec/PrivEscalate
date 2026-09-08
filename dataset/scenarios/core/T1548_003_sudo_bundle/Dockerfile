FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_bundle
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/bundle as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and ruby-bundler (which provides /usr/bin/bundle)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        ruby \
        bundler \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify bundle is installed
RUN which bundle && ls -la /usr/bin/bundle

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# bundle can be used to execute arbitrary commands when run as root.
# The exploit approach:
#   sudo BUNDLE_GEMFILE=x bundle exec /bin/sh
# This spawns a root shell because bundle exec runs the given command
# in the context of the bundle, and since sudo grants root, the shell is root.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/bundle" > /etc/sudoers.d/bundle && \
    chmod 440 /etc/sudoers.d/bundle

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