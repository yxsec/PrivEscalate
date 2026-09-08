FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_dvips
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/dvips as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and dvips (part of texlive-binaries)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        texlive-binaries \
        texlive-latex-base \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify dvips is installed
RUN which dvips && ls -la /usr/bin/dvips

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Create a minimal .dvi file that dvips can process.
# We use latex to generate texput.dvi in the user's home directory.
# dvips with -R0 disables secure mode, allowing \special commands to run shell commands.
RUN cd /home/lowpriv && \
    echo '\\documentclass{article}\\begin{document}Hello\\end{document}' > texput.tex && \
    latex texput.tex && \
    chown lowpriv:lowpriv texput.* && \
    ls -la texput.dvi

# --- Configure sudo vulnerability ---
# dvips -R0 disables the "secure" mode restriction, allowing arbitrary shell
# command execution via PostScript \special commands or the 'E' interactive option.
# The attacker can use: sudo dvips -R0 texput.dvi -o /dev/null
# and leverage the PostScript interpreter or header file inclusion to execute commands as root.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/dvips" > /etc/sudoers.d/dvips && \
    chmod 440 /etc/sudoers.d/dvips

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