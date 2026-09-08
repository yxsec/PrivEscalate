FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_bash
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/bash as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server and sudo
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify bash is installed
RUN which bash && ls -la /usr/bin/bash

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# Allowing a user to run bash as root via sudo gives them a direct root shell
# Exploit: sudo /usr/bin/bash -> instant root shell
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/bash" > /etc/sudoers.d/bash && \
    chmod 440 /etc/sudoers.d/bash

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