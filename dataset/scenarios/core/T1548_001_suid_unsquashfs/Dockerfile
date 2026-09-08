FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on unsquashfs
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on /usr/bin/unsquashfs allows
#   privilege escalation by extracting a crafted squashfs image
#   containing a SUID root shell or sensitive files like /etc/shadow
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server and squashfs-tools (provides unsquashfs and mksquashfs)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-server \
        squashfs-tools \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Create a crafted squashfs image containing a SUID root shell
# This simulates the attack payload that the low-priv user can extract
RUN mkdir -p /tmp/payload && \
    cp /bin/sh /tmp/payload/sh && \
    chmod u+s /tmp/payload/sh && \
    chown root:root /tmp/payload/sh && \
    mksquashfs /tmp/payload /home/lowpriv/payload.sqfs -noappend -quiet && \
    chown lowpriv:lowpriv /home/lowpriv/payload.sqfs && \
    rm -rf /tmp/payload

# Inject vulnerability: set SUID bit on unsquashfs
RUN chmod u+s /usr/bin/unsquashfs

# Verify vulnerability is in place
RUN ls -la /usr/bin/unsquashfs | grep -q "rws" && echo "SUID bit confirmed on unsquashfs"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]