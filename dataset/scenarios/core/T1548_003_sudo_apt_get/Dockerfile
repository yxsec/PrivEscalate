FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_apt-get
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/apt-get as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and apt-get (already present but ensure sudo is installed)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify apt-get is installed
RUN which apt-get && ls -la /usr/bin/apt-get

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# apt-get has a changelog command that invokes a pager, and Pre-Invoke/Post-Invoke
# hooks can run arbitrary commands. With sudo, the user can:
#   sudo apt-get changelog apt
#   then !/bin/sh from the pager (less) to get a root shell
# Or: sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/apt-get" > /etc/sudoers.d/apt-get && \
    chmod 440 /etc/sudoers.d/apt-get

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