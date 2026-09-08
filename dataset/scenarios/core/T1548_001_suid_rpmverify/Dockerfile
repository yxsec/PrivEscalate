FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on rpm/rpmverify
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on /usr/bin/rpmverify allows
#   privilege escalation via: rpmverify --eval '%(/bin/sh 1>&2)'
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server and rpm (provides rpmverify/rpm --verify)
# On Debian, the rpm package provides /usr/bin/rpm but rpmverify
# may be a symlink or the same binary. We need to handle this.
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        rpm \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# On Debian, rpmverify may not exist as a separate binary.
# rpm supports --eval, so we create /usr/bin/rpmverify as a
# symlink to /usr/bin/rpm if it doesn't already exist.
# The exploit uses: rpmverify --eval '%(/bin/sh 1>&2)'
# which works because rpm binary supports --eval macro expansion.
RUN if [ ! -f /usr/bin/rpmverify ]; then \
        ln -s /usr/bin/rpm /usr/bin/rpmverify; \
    fi

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Inject vulnerability: set SUID bit on rpmverify (and the actual rpm binary it points to)
RUN chmod u+s /usr/bin/rpm && \
    chmod u+s /usr/bin/rpmverify 2>/dev/null || true

# Verify vulnerability is in place
RUN ls -la /usr/bin/rpmverify && \
    ls -la /usr/bin/rpm | grep -q "rws" && echo "SUID bit confirmed on rpm/rpmverify"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]