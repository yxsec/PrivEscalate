FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on Perl (simulating CVE-2000-0703)
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on /usr/bin/perl allows
#   privilege escalation via: perl -e 'exec "/bin/sh"'
# The original CVE-2000-0703 targeted suidperl which no longer
# exists in modern Perl. We simulate the SUID-perl escalation
# scenario by setting SUID on /usr/bin/perl itself, which
# allows direct root shell via exec.
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server and perl
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        perl \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Inject vulnerability: set SUID bit on perl
# This simulates the CVE-2000-0703 suidperl scenario where perl
# runs with elevated privileges. Modern perl no longer ships
# suidperl, so we set SUID on perl itself.
RUN chmod u+s /usr/bin/perl

# Verify vulnerability is in place
RUN ls -la /usr/bin/perl | grep -q "rws" && echo "SUID bit confirmed on perl"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]