FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on /usr/bin/hg (Mercurial)
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on /usr/bin/hg allows
#   privilege escalation via shell escape
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server and mercurial (provides /usr/bin/hg)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        mercurial \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Inject vulnerability: set SUID bit on hg
# hg is a Python-based tool; with SUID, it can be abused to spawn a root shell
# We create a small SUID C wrapper that execs hg with preserved privileges.
RUN apt-get update && \
    apt-get install -y gcc && \
    printf '#include <unistd.h>\n#include <stdlib.h>\nint main(int argc, char **argv) { setuid(0); setgid(0); argv[0]="/usr/bin/hg.real"; execv("/usr/bin/hg.real", argv); return 1; }\n' > /tmp/hg_wrapper.c && \
    mv /usr/bin/hg /usr/bin/hg.real && \
    gcc -o /usr/bin/hg /tmp/hg_wrapper.c && \
    chown root:root /usr/bin/hg && \
    chmod 4755 /usr/bin/hg && \
    rm -f /tmp/hg_wrapper.c && \
    apt-get purge -y gcc && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

# Verify vulnerability is in place
# ls -la output format may vary; the SUID bit shows as 's' or 'S' in the owner execute field.
# Use stat to reliably check the SUID bit (mode 4xxx).
RUN stat -c '%a' /usr/bin/hg | grep -q '^4' && echo "SUID bit confirmed on /usr/bin/hg"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]