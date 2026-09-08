FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on /usr/bin/ex
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on /usr/bin/ex allows
#   privilege escalation via: ex -c ':!/bin/sh -p'
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server and vim (provides /usr/bin/ex)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-server \
        vim \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Inject vulnerability: set SUID bit on /usr/bin/ex
# /usr/bin/ex is a symlink (or alternative link) to vim.
# We need to replace the symlink with a copy so we can set SUID on it directly,
# or set SUID on the actual binary. Since ex is typically an alternative symlink,
# let's set SUID on the resolved binary and also make ex a hard copy if needed.
RUN REAL_EX=$(readlink -f /usr/bin/ex) && \
    chmod u+s "$REAL_EX" && \
    if [ -L /usr/bin/ex ]; then \
        cp --remove-destination "$REAL_EX" /usr/bin/ex && \
        chmod u+s /usr/bin/ex; \
    else \
        chmod u+s /usr/bin/ex; \
    fi

# Verify vulnerability is in place
# /usr/bin/ex is now a real file with SUID; ls -la will show "rws" in the owner permissions
RUN ls -la /usr/bin/ex && ls -la /usr/bin/ex | grep -q "rws" && echo "SUID bit confirmed on ex"
RUN REAL_EX=$(readlink -f /usr/bin/ex) && ls -la "$REAL_EX" && ls -la "$REAL_EX" | grep -q "rws" && echo "SUID bit confirmed on target binary"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]