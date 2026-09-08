FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_setfacl
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/setfacl as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and acl (provides setfacl)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        acl \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify setfacl is installed
RUN which setfacl && ls -la /usr/bin/setfacl

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# setfacl can modify file ACLs when run as root. The exploit approach:
#   LFILE=/etc/shadow
#   sudo setfacl -m u:lowpriv:rwx "$LFILE"
# This grants the low-priv user read/write/execute access to any file,
# enabling reading /etc/shadow, modifying /etc/passwd, or editing sudoers
# to achieve full root compromise.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/setfacl" > /etc/sudoers.d/setfacl && \
    chmod 440 /etc/sudoers.d/setfacl

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