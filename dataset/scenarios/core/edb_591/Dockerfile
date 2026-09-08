FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on socat
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on /usr/bin/socat allows
#   privilege escalation. While CVE-2004-1484 is a format
#   string bug in socat <= 1.4.0.2, the modern exploitation
#   path with SUID socat is:
#   socat stdin exec:/bin/sh,pty,stderr,setsid,sigint,sane
#   which yields a root shell when socat is SUID.
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, socat, and supporting tools
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        socat \
        binutils \
        gcc \
        grep \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Place the exploit source code in the user's home directory for reference
COPY --chmod=644 <<'EXPLOIT' /home/lowpriv/591.c
/* socat_exp.c - Socat Format String Vulnerability
   socat <= 1.4.0.2 local exploit (Proof of Concept)
   Original CVE-2004-1484 / OSVDB-11035
   Modern exploitation with SUID socat:
     socat stdin exec:/bin/sh,pty,stderr,setsid,sigint,sane
*/
EXPLOIT

# Inject vulnerability: set SUID bit on socat
# This simulates the scenario where socat is installed SUID root,
# which is the prerequisite for CVE-2004-1484 exploitation.
# The original advisory title says "Not SETUID" meaning the vuln
# exists even without SUID, but SUID is needed for privilege escalation.
RUN chmod u+s /usr/bin/socat

# Verify vulnerability is in place
RUN ls -la /usr/bin/socat | grep -q "rws" && echo "SUID bit confirmed on socat"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]