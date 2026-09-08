FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_torsocks
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/torsocks as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and torsocks
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        torsocks \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify torsocks is installed
RUN which torsocks && ls -la /usr/bin/torsocks

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# torsocks is a wrapper that can execute arbitrary commands.
# When allowed via sudo, the attacker can simply run:
#   sudo torsocks /bin/sh
# This spawns a root shell because torsocks executes the given command
# with the LD_PRELOAD of the torsocks library, but the command itself
# runs as root due to sudo.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/torsocks" > /etc/sudoers.d/torsocks && \
    chmod 440 /etc/sudoers.d/torsocks

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