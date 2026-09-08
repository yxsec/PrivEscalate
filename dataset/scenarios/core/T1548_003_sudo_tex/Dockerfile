FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_tex
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/tex as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and TeX
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        texlive-binaries \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify tex is installed
RUN which tex && ls -la /usr/bin/tex

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# tex with --shell-escape allows executing arbitrary shell commands.
# Exploit: sudo tex --shell-escape '\immediate\write18{/bin/sh}'
# This spawns a root shell via TeX's \write18 shell escape mechanism.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/tex" > /etc/sudoers.d/tex && \
    chmod 440 /etc/sudoers.d/tex

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