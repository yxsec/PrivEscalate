FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_check_by_ssh
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/check_by_ssh as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and monitoring-plugins (which provides check_by_ssh)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        monitoring-plugins-basic \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# check_by_ssh is part of monitoring-plugins-basic and typically installed to
# /usr/lib/nagios/plugins/check_by_ssh. Create a symlink to /usr/bin/ for
# consistency with the scenario description.
RUN if [ -f /usr/lib/nagios/plugins/check_by_ssh ]; then \
        ln -sf /usr/lib/nagios/plugins/check_by_ssh /usr/bin/check_by_ssh; \
    fi

# Verify check_by_ssh is available
RUN ls -la /usr/bin/check_by_ssh && /usr/bin/check_by_ssh --help || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# check_by_ssh allows executing arbitrary commands on a remote host via SSH.
# When run as root via sudo, an attacker can use it to connect back to localhost
# (or the same host) and execute arbitrary commands as root.
# Exploit approach:
#   1. Generate SSH key for root or use existing connectivity
#   2. sudo check_by_ssh -H 127.0.0.1 -C '/bin/bash -i' 
#   Or more directly, check_by_ssh has a -C option that specifies the command
#   to run on the remote host. If the attacker sets up SSH keys or uses the
#   local host, they can get a root shell.
#   Simplest: sudo check_by_ssh -H 127.0.0.1 -l root -C 'cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash'
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/check_by_ssh" > /etc/sudoers.d/check_by_ssh && \
    chmod 440 /etc/sudoers.d/check_by_ssh

# Set up root SSH key so check_by_ssh can connect to localhost as root
RUN ssh-keygen -t ed25519 -f /root/.ssh/id_ed25519 -N "" -q && \
    cat /root/.ssh/id_ed25519.pub >> /root/.ssh/authorized_keys && \
    chmod 600 /root/.ssh/authorized_keys

# Pre-accept localhost host key to avoid interactive prompt
RUN mkdir -p /etc/ssh && \
    ssh-keygen -A && \
    ssh-keyscan -H 127.0.0.1 >> /root/.ssh/known_hosts 2>/dev/null; \
    ssh-keyscan -H localhost >> /root/.ssh/known_hosts 2>/dev/null; \
    true

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