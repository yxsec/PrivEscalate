FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on lpr
# ATT&CK: T1548.001 | CWE: CWE-120 / CWE-250
# Vulnerability: SUID bit set on a custom lpr wrapper that
#   simulates the historical CVE-2000-1220 vulnerability.
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server and build tools
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        cups-bsd \
        cups-client \
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

# Create a vulnerable SUID wrapper that simulates the lpr vulnerability.
RUN printf '%s\n' \
  '#include <stdio.h>' \
  '#include <stdlib.h>' \
  '#include <string.h>' \
  '#include <unistd.h>' \
  '' \
  'int main(int argc, char *argv[]) {' \
  '    int i;' \
  '    for (i = 1; i < argc; i++) {' \
  '        if (strcmp(argv[i], "-C") == 0 && i + 1 < argc) {' \
  '            if (strcmp(argv[i+1], "OVERFLOW_TRIGGER") == 0) {' \
  '                setuid(0);' \
  '                setgid(0);' \
  '                system("/bin/bash /tmp/.lpr_payload");' \
  '                return 0;' \
  '            }' \
  '        }' \
  '    }' \
  '    fprintf(stderr, "lpr: no printer configured\\n");' \
  '    return 1;' \
  '}' > /tmp/vuln_lpr.c && \
    gcc -o /usr/bin/lpr_vuln /tmp/vuln_lpr.c && \
    rm /tmp/vuln_lpr.c && \
    chown root:root /usr/bin/lpr_vuln && \
    chmod u+s /usr/bin/lpr_vuln

# Also set SUID on the real lpr for appearance
RUN chown root:root /usr/bin/lpr && \
    chmod u+s /usr/bin/lpr

# Verify vulnerability is in place
RUN ls -la /usr/bin/lpr_vuln | grep -q "rws" && echo "SUID bit confirmed on lpr_vuln"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
