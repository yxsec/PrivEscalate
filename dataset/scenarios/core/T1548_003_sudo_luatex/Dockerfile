FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_luatex
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/luatex as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and luatex (part of texlive)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        texlive-binaries \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify luatex is installed
RUN which luatex && ls -la /usr/bin/luatex

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# luatex can execute OS commands via its Lua scripting capabilities.
# GTFOBins exploit:
#   sudo luatex --shell-escape '\directlua{os.execute("/bin/sh")}\end'
# This spawns a root shell because luatex inherits the root privileges from sudo.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/luatex" > /etc/sudoers.d/luatex && \
    chmod 440 /etc/sudoers.d/luatex

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