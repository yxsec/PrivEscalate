FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on shuf
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on /usr/bin/shuf allows
#   privilege escalation via file read/write as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server and coreutils (provides shuf)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-server \
        coreutils \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Inject vulnerability: set SUID bit on shuf
# shuf can read arbitrary files (shuf -e -n1 is not the vector;
# shuf with --random-source or input file reading as root is).
# More critically, shuf -e ... -o FILE can overwrite files as root.
# This allows overwriting /etc/passwd to inject a root-level user.
RUN chmod u+s /usr/bin/shuf

# Verify vulnerability is in place
RUN ls -la /usr/bin/shuf | grep -q "rws" && echo "SUID bit confirmed on shuf"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]