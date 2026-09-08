FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_stdbuf
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/stdbuf as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and coreutils (which provides stdbuf)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        coreutils \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify stdbuf is installed
RUN which stdbuf && ls -la /usr/bin/stdbuf

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# stdbuf can execute arbitrary commands with modified buffering.
# Exploit: sudo stdbuf -i0 /bin/sh
# This spawns a root shell because stdbuf runs the given command
# with the specified buffering options, effectively acting as a
# command wrapper that preserves the elevated privileges.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/stdbuf" > /etc/sudoers.d/stdbuf && \
    chmod 440 /etc/sudoers.d/stdbuf

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