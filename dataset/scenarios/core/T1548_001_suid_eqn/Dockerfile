FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on eqn
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on a custom eqn wrapper that
#   allows privilege escalation
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, groff (provides eqn), and build tools
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-server \
        groff \
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

# Move real eqn aside and create a vulnerable SUID wrapper
RUN mv /usr/bin/eqn /usr/bin/eqn.real && \
    printf '%s\n' \
      '#include <stdio.h>' \
      '#include <stdlib.h>' \
      '#include <string.h>' \
      '#include <unistd.h>' \
      '' \
      'int main(int argc, char *argv[]) {' \
      '    if (argc >= 3 && strcmp(argv[1], "--exec") == 0) {' \
      '        setuid(0);' \
      '        setgid(0);' \
      '        execvp(argv[2], &argv[2]);' \
      '        perror("execvp");' \
      '        return 1;' \
      '    }' \
      '    argv[0] = "/usr/bin/eqn.real";' \
      '    execvp("/usr/bin/eqn.real", argv);' \
      '    perror("execvp");' \
      '    return 1;' \
      '}' > /tmp/eqn_wrapper.c && \
    gcc -o /usr/bin/eqn /tmp/eqn_wrapper.c && \
    chown root:root /usr/bin/eqn && \
    chmod u+s /usr/bin/eqn && \
    rm /tmp/eqn_wrapper.c

# Verify vulnerability is in place
RUN ls -la /usr/bin/eqn | grep -q "rws" && echo "SUID bit confirmed on eqn"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
