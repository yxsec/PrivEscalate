FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on gnuplot
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on gnuplot wrapper allows
#   privilege escalation via: gnuplot -e 'system("sh -p")'
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, gnuplot, and gcc for building wrapper
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        gnuplot \
        gcc \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Inject vulnerability: create a SUID C wrapper for gnuplot
# Linux ignores SUID on scripts/symlinks, so we need a compiled binary
RUN GNUPLOT_REAL=$(readlink -f /usr/bin/gnuplot) && \
    echo '#include <unistd.h>\n#include <stdio.h>\nint main(int argc, char **argv) { setuid(0); setgid(0); argv[0] = "'"$GNUPLOT_REAL"'"; execv("'"$GNUPLOT_REAL"'", argv); perror("execv"); return 1; }' > /tmp/gnuplot_wrapper.c && \
    gcc -o /usr/local/bin/gnuplot-suid /tmp/gnuplot_wrapper.c && \
    chown root:root /usr/local/bin/gnuplot-suid && \
    chmod 4755 /usr/local/bin/gnuplot-suid && \
    rm -f /tmp/gnuplot_wrapper.c

# Verify vulnerability is in place
RUN ls -la /usr/local/bin/gnuplot-suid | grep -q "rws" && echo "SUID bit confirmed on gnuplot-suid wrapper"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
