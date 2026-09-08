FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_sort
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/sort as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and coreutils (which provides sort)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        coreutils \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify sort is installed
RUN which sort && ls -la /usr/bin/sort

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# sort can read arbitrary files when run as root. The exploit approach:
#   LFILE=/etc/shadow
#   sudo sort -m "$LFILE"
# This allows reading any privileged file. Combined with reading /etc/shadow
# and cracking root password, or reading SSH private keys, this leads to
# full root compromise. Additionally, sort can be used to write files:
#   echo 'DATA' | sudo sort -o /etc/passwd
# which enables overwriting /etc/passwd with a known root password hash.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/sort" > /etc/sudoers.d/sort && \
    chmod 440 /etc/sudoers.d/sort

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