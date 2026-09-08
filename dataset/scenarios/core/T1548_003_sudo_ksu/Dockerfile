FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_ksu
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/ksu as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and Kerberos user commands (ksu is part of krb5-user)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        krb5-user \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# ksu may be installed in different locations depending on the package
# Find it and ensure it's available at /usr/bin/ksu
RUN which ksu || find / -name ksu 2>/dev/null; \
    if [ ! -f /usr/bin/ksu ]; then \
        KSU_PATH=$(find / -name ksu -type f 2>/dev/null | head -1); \
        if [ -n "$KSU_PATH" ]; then \
            ln -sf "$KSU_PATH" /usr/bin/ksu; \
        fi; \
    fi && \
    ls -la /usr/bin/ksu

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# ksu can execute arbitrary commands. The exploit:
#   sudo ksu -q -e /bin/sh
# This spawns a root shell.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/ksu" > /etc/sudoers.d/ksu && \
    chmod 440 /etc/sudoers.d/ksu

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