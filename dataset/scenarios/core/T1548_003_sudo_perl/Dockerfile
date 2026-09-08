FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_perl
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/perl as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and perl
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        perl \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify perl is installed
RUN which perl && ls -la /usr/bin/perl

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# perl can execute arbitrary commands as root via:
#   sudo perl -e 'exec "/bin/sh"'
# This gives an interactive root shell immediately.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/perl" > /etc/sudoers.d/perl && \
    chmod 440 /etc/sudoers.d/perl

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