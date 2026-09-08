FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_certbot
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/certbot as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, certbot
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        certbot \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify certbot is installed
RUN which certbot && ls -la /usr/bin/certbot

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/certbot" > /etc/sudoers.d/certbot && \
    chmod 440 /etc/sudoers.d/certbot

# Verify sudo configuration
RUN visudo -c

# Keep SUID on sudo (removing it and using setcap fails in many container runtimes)
RUN chmod u+s /usr/bin/sudo

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
