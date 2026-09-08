FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_tbl
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/tbl as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and groff (which provides tbl)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        groff \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify tbl is installed
RUN which tbl && ls -la /usr/bin/tbl

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# tbl is a groff preprocessor that reads files. When run as root via sudo,
# it can be used to read arbitrary files (e.g., /etc/shadow).
# Additionally, tbl processes input that can reference external files,
# and combined with groff pipeline features, can lead to command execution.
# The exploit: sudo tbl /etc/shadow (reads privileged files)
# Or more advanced: use .cf or .pi groff requests to execute commands.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/tbl" > /etc/sudoers.d/tbl && \
    chmod 440 /etc/sudoers.d/tbl

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