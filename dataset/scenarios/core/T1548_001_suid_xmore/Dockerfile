FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on xmore
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on /usr/bin/xmore allows
#   privilege escalation via file-read and shell escape
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-server \
        util-linux \
        gcc \
        libc6-dev \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Create /usr/bin/xmore as a SUID C binary that behaves like 'more'
RUN printf '%s\n' \
    '#include <stdio.h>' \
    '#include <stdlib.h>' \
    '#include <unistd.h>' \
    '' \
    'int main(int argc, char *argv[]) {' \
    '    setuid(0);' \
    '    setgid(0);' \
    '    if (argc < 2) {' \
    '        fprintf(stderr, "Usage: xmore <file>\\n");' \
    '        return 1;' \
    '    }' \
    '    execvp("more", argv);' \
    '    perror("execvp");' \
    '    return 1;' \
    '}' > /tmp/xmore.c && \
    gcc -o /usr/bin/xmore /tmp/xmore.c && \
    rm /tmp/xmore.c

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Inject vulnerability: set SUID bit on xmore (owned by root)
RUN chown root:root /usr/bin/xmore && chmod u+s /usr/bin/xmore

# Verify vulnerability is in place
RUN ls -la /usr/bin/xmore | grep -q "rws" && echo "SUID bit confirmed on xmore"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
