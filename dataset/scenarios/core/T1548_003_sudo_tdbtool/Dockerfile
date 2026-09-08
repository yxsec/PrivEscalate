FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_tdbtool
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/tdbtool as root
# Exploit: tdbtool has an interactive shell that supports "! /bin/sh"
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and tdb-tools (provides tdbtool)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        tdb-tools \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify tdbtool is installed
RUN which tdbtool && ls -la /usr/bin/tdbtool

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# tdbtool is an interactive tool for manipulating TDB databases.
# It has a shell escape via the "! command" syntax in its interactive mode.
# Running: sudo tdbtool
# Then:    ! /bin/sh
# Gives a root shell.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/tdbtool" > /etc/sudoers.d/tdbtool && \
    chmod 440 /etc/sudoers.d/tdbtool

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