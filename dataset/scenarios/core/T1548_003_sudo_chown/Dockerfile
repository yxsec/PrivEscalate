FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_chown
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/chown as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and coreutils (chown is part of coreutils)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        coreutils \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify chown is installed
RUN which chown && ls -la /usr/bin/chown

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# chown can change ownership of arbitrary files when run as root.
# The exploit approach (GTFOBins):
#   LFILE=/etc/shadow
#   sudo chown $(id -un):$(id -gn) $LFILE
# This allows the attacker to take ownership of critical files like /etc/shadow
# or /etc/passwd, then modify them to gain root access (e.g., insert a root
# password hash or add a uid=0 user).
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/chown" > /etc/sudoers.d/chown && \
    chmod 440 /etc/sudoers.d/chown

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