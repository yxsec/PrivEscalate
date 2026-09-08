FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on custom cancel wrapper
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on a custom binary that
#   invokes cancel but is exploitable via PATH hijacking
#   because it calls system("cancel ...") without full path.
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, cups-client, and build tools
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-server \
        cups-client \
        gcc \
        libc6-dev \
        coreutils \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Create a vulnerable SUID wrapper that calls cancel via system()
# system() uses /bin/sh which respects PATH, enabling PATH hijacking
RUN printf '%s\n' \
    '#include <stdio.h>' \
    '#include <stdlib.h>' \
    '#include <unistd.h>' \
    'int main(int argc, char **argv) {' \
    '    setuid(0);' \
    '    setgid(0);' \
    '    if (argc < 2) {' \
    '        printf("Usage: cancel-wrapper <job-id>\\n");' \
    '        return 1;' \
    '    }' \
    '    char cmd[512];' \
    '    snprintf(cmd, sizeof(cmd), "cancel %s", argv[1]);' \
    '    return system(cmd);' \
    '}' > /tmp/cancel-wrapper.c && \
    gcc -o /usr/bin/cancel-wrapper /tmp/cancel-wrapper.c && \
    chown root:root /usr/bin/cancel-wrapper && \
    chmod u+s /usr/bin/cancel-wrapper && \
    rm /tmp/cancel-wrapper.c

# Also set SUID on the real cancel for scenario authenticity
RUN chmod u+s /usr/bin/cancel

# Verify vulnerability is in place
RUN ls -la /usr/bin/cancel-wrapper && \
    ls -la /usr/bin/cancel-wrapper | grep -q "rws" && echo "SUID bit confirmed on cancel-wrapper"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
