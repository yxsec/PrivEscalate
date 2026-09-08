FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_lua
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/lua as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and Lua
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        lua5.4 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify lua is installed
RUN which lua5.4 && ls -la /usr/bin/lua5.4

# Create a symlink so /usr/bin/lua points to lua5.4
RUN ln -sf /usr/bin/lua5.4 /usr/bin/lua

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# Lua can execute arbitrary OS commands via os.execute().
# Exploit: sudo lua -e 'os.execute("/bin/sh")'
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/lua" > /etc/sudoers.d/lua && \
    chmod 440 /etc/sudoers.d/lua

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