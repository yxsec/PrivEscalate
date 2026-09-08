FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_sg
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/sg as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and coreutils (sg is part of login/shadow package)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        login \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify sg is installed
RUN which sg && ls -la /usr/bin/sg

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# sg (switch group) can execute commands in the context of a specified group.
# When run via sudo as root, "sudo sg root" drops into a root shell because
# sg spawns a shell with the specified group, and since we're already root
# via sudo, we get a full root shell.
# Exploit: sudo sg root
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/sg" > /etc/sudoers.d/sg && \
    chmod 440 /etc/sudoers.d/sg

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