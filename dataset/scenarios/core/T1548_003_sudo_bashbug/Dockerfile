FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_bashbug
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/bashbug as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and bash (which includes bashbug)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        bash \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify bashbug is installed
RUN which bashbug && ls -la /usr/bin/bashbug

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# bashbug is a shell script that invokes an editor (EDITOR env var or default).
# GTFOBins documents that when run via sudo, the user can set EDITOR to a shell
# or exploit the inherited shell functions. The exploit approach:
#   sudo EDITOR=/bin/bash bashbug
# This opens a root shell because bashbug calls $EDITOR on a temp file.
# With env_keep or NOPASSWD + ability to pass env, this grants root.
RUN echo "lowpriv ALL=(root) NOPASSWD: SETENV: /usr/bin/bashbug" > /etc/sudoers.d/bashbug && \
    chmod 440 /etc/sudoers.d/bashbug

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