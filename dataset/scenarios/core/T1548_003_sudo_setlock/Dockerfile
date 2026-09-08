FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_setlock
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/setlock as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and daemontools (provides setlock)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        daemontools \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# setlock from daemontools may be installed in /usr/bin or /usr/local/bin
# Find it and ensure it's at /usr/bin/setlock
RUN which setlock && ls -la $(which setlock) || true
RUN if [ ! -f /usr/bin/setlock ]; then \
        SETLOCK_PATH=$(which setlock 2>/dev/null || find / -name setlock -type f 2>/dev/null | head -1); \
        if [ -n "$SETLOCK_PATH" ] && [ "$SETLOCK_PATH" != "/usr/bin/setlock" ]; then \
            ln -sf "$SETLOCK_PATH" /usr/bin/setlock; \
        fi; \
    fi && \
    ls -la /usr/bin/setlock

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# setlock acquires a lock on a file and then executes a command.
# Exploit: sudo setlock - /bin/sh
# The "-" flag means don't block if lock fails, and /bin/sh is the command to run.
# This gives a root shell.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/setlock" > /etc/sudoers.d/setlock && \
    chmod 440 /etc/sudoers.d/setlock

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