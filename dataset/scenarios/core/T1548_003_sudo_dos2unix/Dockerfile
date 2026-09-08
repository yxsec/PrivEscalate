FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_dos2unix
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/dos2unix as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and dos2unix
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        dos2unix \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify dos2unix is installed
RUN which dos2unix && ls -la /usr/bin/dos2unix

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# dos2unix with -f -n (or -f -O) can overwrite arbitrary files when run as root.
# The exploit approach:
#   1. Create a crafted /etc/passwd (or /etc/shadow) entry with a known root password
#   2. Use: sudo dos2unix -f -n /tmp/crafted_passwd /etc/passwd
#   This overwrites /etc/passwd with attacker-controlled content, granting root access.
# Alternatively, dos2unix can read sensitive files via:
#   sudo dos2unix -f /etc/shadow (converts in-place but reveals content via error/output)
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/dos2unix" > /etc/sudoers.d/dos2unix && \
    chmod 440 /etc/sudoers.d/dos2unix

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