FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_xdg-user-dir
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running xdg-user-dirs-update as root
# xdg-user-dirs-update is a shell script that sources user-dirs.dirs
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and xdg-user-dirs
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        xdg-user-dirs \
        coreutils \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# Allow lowpriv to run xdg-user-dirs-update as root with NOPASSWD
# Also allow env_keep of XDG_CONFIG_HOME so attacker can point to their own config
RUN echo 'Defaults:lowpriv env_keep += "XDG_CONFIG_HOME XDG_CONFIG_DIRS HOME"' > /etc/sudoers.d/xdg-user-dir && \
    echo 'lowpriv ALL=(root) NOPASSWD: /usr/bin/xdg-user-dirs-update' >> /etc/sudoers.d/xdg-user-dir && \
    chmod 440 /etc/sudoers.d/xdg-user-dir

# Also give sudo NOPASSWD on xdg-user-dir for the original scenario name
RUN echo 'lowpriv ALL=(root) NOPASSWD: /usr/bin/xdg-user-dir' >> /etc/sudoers.d/xdg-user-dir && \
    chmod 440 /etc/sudoers.d/xdg-user-dir

# Ensure cp and chmod are available with SUID for the exploit chain
RUN chmod u+s /usr/bin/sudo

# Verify sudo configuration
RUN visudo -c

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
