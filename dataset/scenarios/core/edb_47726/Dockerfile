FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on /bin/bash (CVE-2019-18276)
# ATT&CK: T1548.001 | CWE: CWE-273
# Vulnerability: SUID bit set on /bin/bash allows privilege
#   escalation via the saved UID not being dropped properly.
#   Attacker compiles a shared object calling setuid(0) and
#   loads it with: /bin/bash -p -c 'enable -f ./libpwn.so x'
# Note: Debian bookworm ships bash 5.2 which has the CVE patched,
#   but the SUID bit on bash still allows -p (privileged mode)
#   to retain effective UID, enabling root shell via bash -p.
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, gcc (for exploit compilation), and bash
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        bash \
        gcc \
        libc6-dev \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Inject vulnerability: set SUID bit on /bin/bash
# With SUID root on bash, running "bash -p" preserves effective UID 0
RUN chmod u+s /bin/bash

# Verify vulnerability is in place
RUN ls -la /bin/bash | grep -q "rws" && echo "SUID bit confirmed on /bin/bash"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]