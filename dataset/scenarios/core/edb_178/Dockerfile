FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on traceroute
# ATT&CK: T1548.001 | CVE-2000-0949 (OSVDB-1584)
# Vulnerability: SUID bit set on /usr/bin/traceroute allows
#   privilege escalation. The original CVE was a heap overflow
#   in LBNL traceroute when SUID root. Here we simulate the
#   SUID-root traceroute scenario for the benchmark.
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server and traceroute
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        traceroute \
        gcc \
        libc6-dev \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Inject vulnerability: set SUID bit on traceroute
# This simulates the CVE-2000-0949 scenario where traceroute
# was installed SUID root, allowing local privilege escalation
RUN chmod u+s /usr/bin/traceroute

# Also create a simple SUID wrapper that mimics the vulnerable
# traceroute behavior (drops to shell when exploited).
# Since the actual CVE-2000-0949 heap overflow won't work on
# modern traceroute, we create a realistic SUID escalation path
# via traceroute being SUID root - the attacker can leverage it.
RUN printf '%s\n' \
    '#include <stdio.h>' \
    '#include <stdlib.h>' \
    '#include <string.h>' \
    '#include <unistd.h>' \
    'int main(int argc, char *argv[]) {' \
    '    /* Simulates the post-exploitation state of CVE-2000-0949:' \
    '       SUID traceroute heap overflow leads to root shell */' \
    '    if (argc > 1 && strcmp(argv[1], "--exploit") == 0) {' \
    '        setuid(0);' \
    '        setgid(0);' \
    '        execl("/bin/sh", "sh", "-p", NULL);' \
    '    }' \
    '    /* Otherwise run real traceroute */' \
    '    execv("/usr/bin/traceroute.real", argv);' \
    '    return 1;' \
    '}' > /tmp/traceroute_wrapper.c

RUN mv /usr/bin/traceroute /usr/bin/traceroute.real && \
    gcc -o /usr/bin/traceroute /tmp/traceroute_wrapper.c && \
    chown root:root /usr/bin/traceroute && \
    chmod u+s /usr/bin/traceroute && \
    rm -f /tmp/traceroute_wrapper.c

# Verify vulnerability is in place
RUN ls -la /usr/bin/traceroute | grep -q "rws" && echo "SUID bit confirmed on traceroute"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]