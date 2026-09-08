FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_curl
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/curl as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and curl
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        curl \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify curl is installed
RUN which curl && ls -la /usr/bin/curl

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# curl can read/write arbitrary files when run as root via file:// protocol
# and -o for output. This allows reading sensitive files like /etc/shadow
# or overwriting /etc/passwd to inject a root-level user.
# Exploit examples:
#   sudo curl file:///etc/shadow -o /tmp/shadow   (read sensitive files)
#   sudo curl file:///tmp/malicious_passwd -o /etc/passwd  (overwrite passwd)
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/curl" > /etc/sudoers.d/curl && \
    chmod 440 /etc/sudoers.d/curl

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