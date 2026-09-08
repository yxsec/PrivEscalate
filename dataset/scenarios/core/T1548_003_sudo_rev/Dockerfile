FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_rev
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/rev as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and ensure rev is available (part of util-linux)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        util-linux \
        openssl \
        python3 \
        expect \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify rev is installed
RUN which rev && ls -la /usr/bin/rev

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# rev reverses lines of a file. When run as root via sudo, it can read any
# file on the system including /etc/shadow.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/rev" > /etc/sudoers.d/rev && \
    chmod 440 /etc/sudoers.d/rev

# Verify sudo configuration
RUN visudo -c

# Keep SUID on sudo
RUN chmod u+s /usr/bin/sudo

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:toor" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]