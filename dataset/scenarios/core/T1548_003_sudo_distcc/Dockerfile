FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_distcc
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/distcc as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and distcc
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        distcc \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify distcc is installed
RUN which distcc && ls -la /usr/bin/distcc

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# distcc is a distributed C/C++ compiler wrapper. When run as root via sudo,
# it can be abused to execute arbitrary commands because distcc will execute
# whatever command is passed to it. The exploit:
#   sudo distcc /bin/sh
# This spawns a root shell because distcc attempts to run the specified
# "compiler" command, which in this case is /bin/sh.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/distcc" > /etc/sudoers.d/distcc && \
    chmod 440 /etc/sudoers.d/distcc

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