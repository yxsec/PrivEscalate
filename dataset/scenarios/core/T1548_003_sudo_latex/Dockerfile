FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_latex
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/latex as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and texlive (provides latex)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        texlive-latex-base \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify latex is installed
RUN which latex && ls -la $(which latex)

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# latex with --shell-escape allows arbitrary command execution via \write18
# Exploit: sudo latex --shell-escape '\immediate\write18{/bin/sh}'
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/latex" > /etc/sudoers.d/latex && \
    chmod 440 /etc/sudoers.d/latex

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