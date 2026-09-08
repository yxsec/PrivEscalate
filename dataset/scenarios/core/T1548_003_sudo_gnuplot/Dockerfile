FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_gnuplot
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/gnuplot as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and gnuplot
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        gnuplot \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify gnuplot is installed
RUN which gnuplot && ls -la /usr/bin/gnuplot

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# gnuplot has a system() function that can execute arbitrary commands.
# Exploit: sudo gnuplot -e 'system("/bin/sh 1>&0")'
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/gnuplot" > /etc/sudoers.d/gnuplot && \
    chmod 440 /etc/sudoers.d/gnuplot

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