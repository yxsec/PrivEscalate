FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_gcc
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/gcc as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and gcc
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        gcc \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify gcc is installed
RUN which gcc && ls -la /usr/bin/gcc

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# gcc supports -wrapper option which allows specifying a program to wrap
# all compiler invocations. The exploit:
#   sudo gcc -wrapper /bin/sh,-s .
# This spawns a root shell because gcc invokes the wrapper program
# with root privileges.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/gcc" > /etc/sudoers.d/gcc && \
    chmod 440 /etc/sudoers.d/gcc

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