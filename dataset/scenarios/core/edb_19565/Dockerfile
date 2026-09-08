FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on simulated cdda2cdr binary
# ATT&CK: T1548.001 | CVE-2000-0362
# Vulnerability: SUID root bit set on /usr/bin/cdda2cdr
#   simulating the cwdtools vulnerability from SuSE 6.1/6.2
#   where cdda2cdr was SUID root, allowing privilege escalation.
#   Modern reproduction: SUID binary that spawns a shell.
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, gcc for compilation, and basic tools
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        gcc \
        libc6-dev \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Create a simulated vulnerable cdda2cdr SUID binary using printf
RUN printf '#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n#include <unistd.h>\nint main(int argc, char *argv[]) {\n  int i;\n  for (i = 1; i < argc; i++) {\n    if (strcmp(argv[i], "-e") == 0 && i + 1 < argc) {\n      setuid(0); setgid(0);\n      execl("/bin/sh", "sh", "-c", argv[i+1], NULL);\n      perror("execl"); return 1;\n    }\n  }\n  fprintf(stderr, "cdda2cdr (cwdtools) - CD writing utility\\n");\n  return 0;\n}\n' > /tmp/cdda2cdr.c && \
    gcc -o /usr/bin/cdda2cdr /tmp/cdda2cdr.c && \
    rm -f /tmp/cdda2cdr.c

# Inject vulnerability: set SUID root bit on cdda2cdr (mimicking SuSE 6.x default)
# chown first, then chmod, because chown can reset the SUID bit
RUN chown root:root /usr/bin/cdda2cdr && \
    chmod u+s /usr/bin/cdda2cdr

# Verify vulnerability is in place
RUN ls -la /usr/bin/cdda2cdr && ls -la /usr/bin/cdda2cdr | grep -q "rws" && echo "SUID bit confirmed on cdda2cdr"

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]