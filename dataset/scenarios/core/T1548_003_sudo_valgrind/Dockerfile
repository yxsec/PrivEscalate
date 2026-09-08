FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_valgrind
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/valgrind as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and valgrind
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        valgrind \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify valgrind is installed
RUN which valgrind && ls -la /usr/bin/valgrind

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# valgrind can execute arbitrary programs. When run as root via sudo:
#   sudo valgrind /bin/sh
# This spawns a root shell directly since valgrind executes the given
# program, and when that program is a shell, the user gets root access.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/valgrind" > /etc/sudoers.d/valgrind && \
    chmod 440 /etc/sudoers.d/valgrind

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