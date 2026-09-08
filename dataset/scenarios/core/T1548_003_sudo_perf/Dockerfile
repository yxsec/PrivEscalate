FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_perf
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/perf as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and linux-perf
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        linux-perf \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# perf is typically installed as a versioned binary with a wrapper at /usr/bin/perf
# Verify perf is installed
RUN which perf && ls -la /usr/bin/perf

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# perf stat can be used to execute arbitrary commands as root:
#   sudo perf stat /bin/sh
# This spawns a root shell directly.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/perf" > /etc/sudoers.d/perf && \
    chmod 440 /etc/sudoers.d/perf

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