FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_lwp-download
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/lwp-download as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and lwp-download (part of libwww-perl)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        libwww-perl \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify lwp-download is installed
RUN which lwp-download && ls -la /usr/bin/lwp-download

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# lwp-download can fetch files from URLs (including file:// URLs) and write them
# to arbitrary paths when run as root. The exploit approach:
#   1. Create a malicious /etc/passwd or /etc/shadow replacement
#   2. Use sudo lwp-download file:///tmp/evil_passwd /etc/passwd
#   This overwrites /etc/passwd with a version containing a root-shell backdoor
#   (e.g., a new uid=0 user with known password or no password).
#   Alternatively, overwrite /etc/sudoers to grant full root access.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/lwp-download" > /etc/sudoers.d/lwp-download && \
    chmod 440 /etc/sudoers.d/lwp-download

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