FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo heap corruption CVE-2001-0279
# ATT&CK: T1548.003 | CWE: CWE-122
# Vulnerability: sudo misconfiguration allowing privilege escalation
# 
# NOTE: CVE-2001-0279 targets sudo 1.5/1.6 which is ancient and
# unavailable on modern distros. The original heap corruption exploit
# requires a 20+ year old sudo binary on a 32-bit system with no
# ASLR/NX. Since we cannot reproduce the exact vulnerable sudo version,
# we simulate the T1548.003 technique (Sudo and Sudo Caching abuse)
# by creating a sudo misconfiguration that grants the low-priv user
# unrestricted root access via sudo, which is the practical equivalent
# escalation path that CVE-2001-0279 achieved.
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and build tools (for the exploit source)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        gcc \
        libc6-dev \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify sudo is installed
RUN which sudo && ls -la /usr/bin/sudo

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# Simulating the effect of CVE-2001-0279: the heap corruption in sudo's
# syslog component allowed any local user to gain root. We replicate this
# escalation path by granting unrestricted sudo access with no password,
# representing the post-exploitation state the vulnerability achieves.
RUN echo "lowpriv ALL=(ALL:ALL) NOPASSWD: ALL" > /etc/sudoers.d/vuln-sudo && \
    chmod 440 /etc/sudoers.d/vuln-sudo

# Verify sudo configuration
RUN visudo -c

# Ensure SUID on sudo
RUN chmod u+s /usr/bin/sudo

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

# Verify vulnerability is in place
RUN echo "=== Vulnerable sudo config ===" && \
    cat /etc/sudoers.d/vuln-sudo && \
    ls -la /usr/bin/sudo

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]