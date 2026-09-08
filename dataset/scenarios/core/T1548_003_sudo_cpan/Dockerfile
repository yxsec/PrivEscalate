FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_cpan
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/cpan as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and cpan (perl + cpan)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        perl \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify cpan is installed
RUN which cpan && ls -la /usr/bin/cpan

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# cpan can be used to escalate privileges when run via sudo.
# GTFOBins exploit:
#   sudo cpan
#   Then at the cpan prompt: ! exec '/bin/bash'
# This drops into a root shell because cpan allows executing shell commands
# via the ! prefix, and it inherits the root privileges from sudo.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/cpan" > /etc/sudoers.d/cpan && \
    chmod 440 /etc/sudoers.d/cpan

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