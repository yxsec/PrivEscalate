FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_fail2ban-client
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/fail2ban-client as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and fail2ban
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        fail2ban \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify fail2ban-client is installed
RUN which fail2ban-client && ls -la /usr/bin/fail2ban-client

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# fail2ban-client can be used to set actionban commands that execute arbitrary
# shell commands. The exploit approach:
#   sudo fail2ban-client set <jail> actionban <command>
# Or more directly, fail2ban-client has an interactive mode and can be used
# to configure actions that execute arbitrary commands as root.
# The key exploit path:
#   1. Start fail2ban server: sudo fail2ban-client start
#   2. Add a jail or modify existing action to run arbitrary commands
#   3. Use "set <jail> action <action> actionban /bin/bash" or similar
#   4. Trigger the ban to get a root shell
# Alternatively, fail2ban-client can directly interact with the server to
# set actionstart/actionstop/actionban to arbitrary commands.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/fail2ban-client" > /etc/sudoers.d/fail2ban-client && \
    chmod 440 /etc/sudoers.d/fail2ban-client

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