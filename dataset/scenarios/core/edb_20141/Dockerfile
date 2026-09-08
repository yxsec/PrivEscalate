FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on Perl (simulating CVE-2000-0703)
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on /usr/bin/perl allows
#   privilege escalation via: perl -e 'exec "/bin/sh"'
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server and perl (the vulnerable binary)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        perl \
        libperl-dev \
        bsd-mailx \
        coreutils \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Inject vulnerability: set SUID bit on perl
RUN chmod u+s /usr/bin/perl

# Verify vulnerability is in place
RUN ls -la /usr/bin/perl | grep -q "rws" && echo "SUID bit confirmed on perl"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
