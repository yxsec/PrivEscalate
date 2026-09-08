FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_tshark
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/tshark as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and tshark
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        tshark \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify tshark is installed
RUN which tshark && ls -la /usr/bin/tshark

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# tshark can be used to execute commands via its -z lua:script functionality
# or via the -c option combined with post-dissector scripts.
# GTFOBins documents that with sudo tshark, one can spawn a shell:
#   SUDO_ASKPASS=/bin/false sudo tshark -c 1 -w /dev/null -i lo -z lua,os.execute("/bin/sh")
# Or use the capture file writing to overwrite sensitive files.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/tshark" > /etc/sudoers.d/tshark && \
    chmod 440 /etc/sudoers.d/tshark

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