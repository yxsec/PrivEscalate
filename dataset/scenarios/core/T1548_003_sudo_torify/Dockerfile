FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_torify
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/torify as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and tor (which provides torify)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        tor \
        torsocks \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify torify is installed
RUN which torify && ls -la /usr/bin/torify

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# torify is a wrapper script that can execute arbitrary commands.
# When allowed via sudo, the user can run: sudo torify /bin/sh
# This spawns a root shell directly.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/torify" > /etc/sudoers.d/torify && \
    chmod 440 /etc/sudoers.d/torify

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