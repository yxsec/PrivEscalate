FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_m4
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/m4 as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and m4
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        m4 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify m4 is installed
RUN which m4 && ls -la /usr/bin/m4

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# m4 supports the esyscmd() macro which executes shell commands.
# When run as root via sudo, this allows arbitrary command execution:
#   echo 'esyscmd(/bin/sh 0<&2 1>&2)' | sudo m4
# This spawns an interactive root shell.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/m4" > /etc/sudoers.d/m4 && \
    chmod 440 /etc/sudoers.d/m4

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