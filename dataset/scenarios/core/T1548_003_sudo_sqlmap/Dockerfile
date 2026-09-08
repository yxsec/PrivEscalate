FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_sqlmap
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/sqlmap as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and sqlmap
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        sqlmap \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify sqlmap is installed
RUN which sqlmap && ls -la /usr/bin/sqlmap

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# sqlmap is a Python-based tool. When run as root via sudo, it can be exploited
# using its --shell or --os-shell functionality, or by leveraging the
# --eval option to execute arbitrary Python code as root:
#   sudo sqlmap --eval="import os; os.execl('/bin/bash','/bin/bash')"
# GTFOBins documents that sqlmap can inherit shell functions for privilege escalation.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/sqlmap" > /etc/sudoers.d/sqlmap && \
    chmod 440 /etc/sudoers.d/sqlmap

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