FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on perl — PerlIO_Debug() 
# CVE-2005-0155 / OSVDB-13451
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on /usr/bin/perl allows
#   privilege escalation via PERLIO_DEBUG env var to create
#   root-owned files (e.g., /etc/ld.so.preload), then use
#   ld.so.preload with a malicious shared library to hijack
#   getuid() and gain root.
#
# NOTE: The original CVE targeted sperl5.8.4 on old Debian.
# Modern perl has mitigations, but setting SUID on perl still
# allows direct escalation via: perl -e 'exec "/bin/sh"'
# with effective uid=0. We set SUID on perl to simulate the
# scenario where suidperl/sperl was installed SUID root.
# The exploit can also use the PERLIO_DEBUG vector or simply
# exec a root shell.
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, perl, gcc (for compiling exploit/shared lib)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        perl \
        gcc \
        libc6-dev \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Inject vulnerability: set SUID bit on /usr/bin/perl
# This simulates the historical sperl/suidperl SUID installation
RUN chmod u+s /usr/bin/perl

# Verify vulnerability is in place
RUN ls -la /usr/bin/perl | grep -q "rws" && echo "SUID bit confirmed on perl"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]