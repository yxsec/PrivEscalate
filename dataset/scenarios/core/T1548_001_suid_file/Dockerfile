FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on custom binary
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on a custom binary that allows
#   privilege escalation
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server and required packages
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        file \
        gcc \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Inject vulnerability: set SUID bit on /usr/bin/file
RUN chmod u+s /usr/bin/file

# Also create a SUID helper that can be discovered and abused.
# This simulates a realistic scenario where an admin created a
# SUID wrapper that invokes 'file' but can be abused via PATH manipulation.
RUN echo '#include <stdio.h>\n#include <stdlib.h>\n#include <unistd.h>\nint main(int argc, char **argv) {\n  setuid(0);\n  setgid(0);\n  if (argc > 1) {\n    system(argv[1]);\n  } else {\n    system("/usr/bin/file --version");\n  }\n  return 0;\n}' > /tmp/filehelper.c && \
    gcc -o /usr/local/bin/filehelper /tmp/filehelper.c && \
    chown root:root /usr/local/bin/filehelper && \
    chmod u+s /usr/local/bin/filehelper && \
    rm /tmp/filehelper.c

# Verify vulnerability is in place
RUN ls -la /usr/bin/file | grep -q "rws" && echo "SUID bit confirmed on /usr/bin/file"
RUN ls -la /usr/local/bin/filehelper | grep -q "rws" && echo "SUID bit confirmed on /usr/local/bin/filehelper"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
