FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_openvpn
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/openvpn as root
# Exploit: sudo openvpn --dev null --script-security 2 --up '/bin/sh -s'
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and openvpn
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        openvpn \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify openvpn is installed
RUN which openvpn && ls -la /usr/sbin/openvpn

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# openvpn with --script-security 2 and --up allows executing arbitrary commands as root.
# The exploit: sudo openvpn --dev null --script-security 2 --up '/bin/sh -s'
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/sbin/openvpn" > /etc/sudoers.d/openvpn && \
    chmod 440 /etc/sudoers.d/openvpn

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