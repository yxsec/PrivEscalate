FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_troff
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/troff as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and groff (which provides troff)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        groff \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify troff is installed
RUN which troff && ls -la /usr/bin/troff

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# troff can execute system commands via its .sy request (or .pi pipe request).
# An attacker can create an input file containing:
#   .sy /bin/sh
# Then run: sudo troff /tmp/exploit.roff
# This spawns a root shell.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/troff" > /etc/sudoers.d/troff && \
    chmod 440 /etc/sudoers.d/troff

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