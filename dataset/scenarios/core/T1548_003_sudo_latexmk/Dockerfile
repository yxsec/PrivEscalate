FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_latexmk
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/latexmk as root
# Known exploit: latexmk -pdf -pdflatex='/bin/sh #' /dev/null
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and latexmk
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        latexmk \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify latexmk is installed
RUN which latexmk && ls -la /usr/bin/latexmk

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# latexmk can execute arbitrary commands via the -pdflatex option.
# Exploit: sudo latexmk -pdf -pdflatex='/bin/sh #' /dev/null
# This spawns a root shell because latexmk invokes the specified
# "pdflatex" command, which is actually /bin/sh.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/latexmk" > /etc/sudoers.d/latexmk && \
    chmod 440 /etc/sudoers.d/latexmk

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