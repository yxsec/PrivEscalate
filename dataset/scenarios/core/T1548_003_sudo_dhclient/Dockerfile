FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_dhclient
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/dhclient as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and dhclient (isc-dhcp-client)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        isc-dhcp-client \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify dhclient is installed
RUN which dhclient && ls -la /usr/sbin/dhclient

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# dhclient supports -sf flag to specify a script file to run as root.
# Exploit: sudo dhclient -sf /bin/sh
# This causes dhclient to execute /bin/sh as root, giving an interactive shell.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/sbin/dhclient" > /etc/sudoers.d/dhclient && \
    chmod 440 /etc/sudoers.d/dhclient

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