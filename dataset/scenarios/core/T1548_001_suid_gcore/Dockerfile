FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on /usr/bin/gcore
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on /usr/bin/gcore allows
#   privilege escalation by dumping memory of privileged
#   processes (e.g., reading /etc/shadow from a root process)
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server and gdb (which provides gcore)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        gdb \
        procps \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# gcore is a shell script that invokes gdb. For SUID escalation we need
# the actual gdb binary to run as root. We create a SUID wrapper that
# executes gcore functionality. However, since gcore is a shell script
# and SUID on scripts doesn't work directly, we set SUID on gdb itself
# (which gcore calls) AND on gcore's wrapper approach.
# 
# The standard GTFOBins approach for gcore: use it to dump a root process
# memory, then extract sensitive data (like shadow hashes or SSH keys).
# For a direct shell approach, gdb with SUID can be used via gcore's
# invocation of gdb.
#
# Set SUID on gcore (script) and on gdb (the binary it calls)
RUN chmod u+s /usr/bin/gdb && \
    chmod u+s /usr/bin/gcore

# Verify vulnerability is in place
RUN ls -la /usr/bin/gcore | grep -q "rws" && echo "SUID bit confirmed on gcore" && \
    ls -la /usr/bin/gdb | grep -q "rws" && echo "SUID bit confirmed on gdb"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]