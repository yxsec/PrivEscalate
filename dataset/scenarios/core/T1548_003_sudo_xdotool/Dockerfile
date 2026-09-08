FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_xdotool
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/xdotool as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, xdotool, and Xvfb for headless X
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        xdotool \
        xvfb \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify xdotool is installed
RUN which xdotool && ls -la /usr/bin/xdotool

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# xdotool has an "exec" subcommand that can execute arbitrary commands.
# When run as root via sudo, it spawns the command as root.
# Also allow Xvfb so the exploit can create a virtual display.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/xdotool, /usr/bin/Xvfb" > /etc/sudoers.d/xdotool && \
    chmod 440 /etc/sudoers.d/xdotool

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
