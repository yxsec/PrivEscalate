FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_cpulimit
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/cpulimit as root
# Known exploit: sudo cpulimit -l 100 -f /bin/sh
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and cpulimit
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        cpulimit \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify cpulimit is installed
RUN which cpulimit && ls -la /usr/bin/cpulimit

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# cpulimit with -f flag can fork and execute arbitrary commands.
# When run as root via sudo, `sudo cpulimit -l 100 -f /bin/sh` spawns
# a root shell because cpulimit executes the given command as a child process.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/cpulimit" > /etc/sudoers.d/cpulimit && \
    chmod 440 /etc/sudoers.d/cpulimit

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