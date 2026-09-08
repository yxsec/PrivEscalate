FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_cp
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/cp as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and coreutils (cp is part of coreutils)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        coreutils \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify cp is installed
RUN which cp && ls -la /usr/bin/cp

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# cp as root can overwrite any file on the system. The exploit approach:
#   1. Read sensitive files: sudo cp /etc/shadow /dev/stdout
#   2. Overwrite /etc/passwd or /etc/shadow with crafted versions to gain root
#   For example, create a modified /etc/passwd with a known root password hash,
#   then: sudo cp /tmp/evil_passwd /etc/passwd
#   Then su to root with the known password.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/cp" > /etc/sudoers.d/cp && \
    chmod 440 /etc/sudoers.d/cp

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