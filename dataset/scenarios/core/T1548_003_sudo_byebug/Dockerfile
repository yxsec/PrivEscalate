FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_byebug
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/byebug as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and ruby with byebug
# byebug is a Ruby debugger gem; we need ruby and the gem
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        ruby \
        ruby-dev \
        build-essential \
    && gem install byebug \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Find where byebug was installed and create a symlink at /usr/bin/byebug if needed
RUN BYEBUG_PATH=$(which byebug) && \
    echo "byebug found at: $BYEBUG_PATH" && \
    if [ "$BYEBUG_PATH" != "/usr/bin/byebug" ]; then \
        ln -sf "$BYEBUG_PATH" /usr/bin/byebug; \
    fi && \
    ls -la /usr/bin/byebug

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Create a minimal Ruby script for byebug to debug (byebug needs a script to load)
RUN echo 'require "byebug"; byebug; puts "done"' > /tmp/target.rb && \
    chmod 644 /tmp/target.rb

# --- Configure sudo vulnerability ---
# byebug is a Ruby debugger. When run as root via sudo, the user can:
#   sudo byebug /tmp/target.rb
# Then at the debugger prompt, execute:
#   system("id")
#   system("/bin/bash")
# This spawns a root shell since byebug inherits the root context from sudo.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/byebug" > /etc/sudoers.d/byebug && \
    chmod 440 /etc/sudoers.d/byebug

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