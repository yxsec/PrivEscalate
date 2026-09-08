FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_taskset
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/taskset as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and util-linux (which provides taskset)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        util-linux \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify taskset is installed
RUN which taskset && ls -la /usr/bin/taskset

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# taskset can execute arbitrary commands with a CPU affinity mask.
# Exploit: sudo taskset 1 /bin/sh  -> spawns a root shell
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/taskset" > /etc/sudoers.d/taskset && \
    chmod 440 /etc/sudoers.d/taskset

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