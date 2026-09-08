FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_telnet
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/telnet as root
# Exploit: sudo telnet -> then !/bin/sh to get root shell
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and telnet client
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        telnet \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify telnet is installed
RUN which telnet && ls -la /usr/bin/telnet

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# telnet has an interactive mode where typing ! followed by a command
# executes it as a shell command. When telnet runs as root via sudo,
# typing !/bin/sh spawns a root shell.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/telnet" > /etc/sudoers.d/telnet && \
    chmod 440 /etc/sudoers.d/telnet

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