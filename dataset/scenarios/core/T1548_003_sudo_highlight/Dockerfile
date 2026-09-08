FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_highlight
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/highlight as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and highlight
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        highlight \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify highlight is installed
RUN which highlight && ls -la /usr/bin/highlight

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# highlight can read arbitrary files when run as root.
# The exploit approach uses highlight's --no-doc --failsafe options to read
# privileged files like /etc/shadow. Additionally, highlight supports
# plug-in scripts and can be abused to execute arbitrary commands via
# its --plug-in option or by leveraging its ability to read files as root.
# Example: sudo highlight --no-doc --failsafe /etc/shadow
# For shell: highlight supports Lua-based plugins which can execute system commands.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/highlight" > /etc/sudoers.d/highlight && \
    chmod 440 /etc/sudoers.d/highlight

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