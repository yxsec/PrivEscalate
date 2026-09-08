FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_cowthink
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/cowthink as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and cowsay (which includes cowthink)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        cowsay \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# cowsay package installs binaries under /usr/games; create symlink so /usr/bin/cowthink exists
RUN ln -sf /usr/games/cowthink /usr/bin/cowthink

# Verify cowthink is installed and accessible
RUN which cowthink && ls -la /usr/bin/cowthink

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# GTFOBins: cowthink (and cowsay) accept a Perl-based format string via the
# TZ environment variable or can be exploited through the -e flag which
# evaluates Perl code. The exploit:
#   sudo cowthink -e 'exec "/bin/sh";'
# This spawns a root shell because cowthink is a Perl script that uses
# the -e option to specify a "tongue" string which gets eval'd in Perl context.
# Actually the GTFOBins approach is:
#   sudo /usr/bin/cowthink -e 'exec "/bin/sh";'
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/cowthink" > /etc/sudoers.d/cowthink && \
    chmod 440 /etc/sudoers.d/cowthink

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