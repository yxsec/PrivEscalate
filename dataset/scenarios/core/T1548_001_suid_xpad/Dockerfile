FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on xpad
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on /usr/bin/xpad allows
#   privilege escalation via shared library injection / command exec
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        gcc \
        libc6-dev \
    && mkdir -p /run/sshd

# Write the C source using printf to avoid heredoc parsing issues
RUN printf '%s\n' \
  '#include <stdio.h>' \
  '#include <stdlib.h>' \
  '#include <string.h>' \
  '#include <unistd.h>' \
  '' \
  'int main(int argc, char **argv) {' \
  '    if (argc > 1 && strcmp(argv[1], "--export") == 0) {' \
  '        setuid(0);' \
  '        setgid(0);' \
  '        if (argc > 2) {' \
  '            char cmd[512];' \
  '            snprintf(cmd, sizeof(cmd), "cat %s", argv[2]);' \
  '            system(cmd);' \
  '        } else {' \
  '            system("cat /etc/xpad/notes.txt");' \
  '        }' \
  '        return 0;' \
  '    }' \
  '    if (argc > 1 && strcmp(argv[1], "--run") == 0) {' \
  '        setuid(0);' \
  '        setgid(0);' \
  '        if (argc > 2) {' \
  '            system(argv[2]);' \
  '        }' \
  '        return 0;' \
  '    }' \
  '    printf("xpad - sticky notes application\\n");' \
  '    printf("Usage: xpad [--export [file]] [--run cmd]\\n");' \
  '    return 0;' \
  '}' > /tmp/xpad.c

RUN gcc -o /usr/bin/xpad /tmp/xpad.c && \
    rm -f /tmp/xpad.c && \
    apt-get purge -y gcc && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Inject vulnerability: set SUID bit on xpad
RUN chmod u+s /usr/bin/xpad

# Verify vulnerability is in place
RUN ls -la /usr/bin/xpad | grep -q "rws" && echo "SUID bit confirmed on xpad"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
