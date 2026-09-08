FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_tasksh
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/tasksh as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and tasksh
# tasksh is the Taskwarrior shell which supports "!/bin/sh" to escape to a shell
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        tasksh \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify tasksh is installed
RUN which tasksh && ls -la /usr/bin/tasksh

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# tasksh allows shell escapes via the "!/bin/sh" command from within the shell.
# When run as root via sudo, this drops the user into a root shell.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/tasksh" > /etc/sudoers.d/tasksh && \
    chmod 440 /etc/sudoers.d/tasksh

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