FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on custom binary (xmodmap replaced)
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on /usr/bin/xmodmap which is a
#   compiled C wrapper that preserves euid and execs commands
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, gcc for building wrapper, and coreutils
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-server \
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

# Build a SUID binary that mimics xmodmap but can be abused
RUN printf '%s\n' \
  '#include <stdio.h>' \
  '#include <stdlib.h>' \
  '#include <string.h>' \
  '#include <unistd.h>' \
  '' \
  'int main(int argc, char *argv[]) {' \
  '    setuid(0);' \
  '    setgid(0);' \
  '    if (argc >= 3 && strcmp(argv[1], "-e") == 0) {' \
  '        system(argv[2]);' \
  '        return 0;' \
  '    }' \
  '    if (argc >= 3 && strcmp(argv[1], "-f") == 0) {' \
  '        FILE *f = fopen(argv[2], "r");' \
  '        if (!f) { perror("fopen"); return 1; }' \
  '        char line[4096];' \
  '        while (fgets(line, sizeof(line), f)) {' \
  '            system(line);' \
  '        }' \
  '        fclose(f);' \
  '        return 0;' \
  '    }' \
  '    fprintf(stderr, "Usage: %s -e expression | -f file\\n", argv[0]);' \
  '    return 1;' \
  '}' > /tmp/xmodmap.c

RUN gcc -o /usr/bin/xmodmap /tmp/xmodmap.c && \
    chown root:root /usr/bin/xmodmap && \
    chmod u+s /usr/bin/xmodmap && \
    rm -f /tmp/xmodmap.c

# Verify vulnerability is in place
RUN ls -la /usr/bin/xmodmap | grep -q "rws" && echo "SUID bit confirmed on xmodmap"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
