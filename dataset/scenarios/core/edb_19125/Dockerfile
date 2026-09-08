FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on tclsh (simulating oratclsh)
# ATT&CK: T1548.001 | CWE: CWE-250 | CVE-1999-0711
# Vulnerability: SUID bit set on tclsh (acting as oratclsh)
#   allows privilege escalation via Tcl commands to write
#   to /etc/passwd and /etc/shadow as root.
# Oracle's oratclsh was essentially a SUID-root Tcl shell.
# We simulate this with standard tclsh + SUID bit.
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server and tcl (provides tclsh, simulating oratclsh)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        tcl \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Simulate Oracle's oratclsh: create a symlink and set SUID root
# The real vulnerability was $ORACLE_HOME/bin/oratclsh with SUID root.
# We create /usr/local/bin/oratclsh as a symlink to tclsh and set SUID.
# Since symlink SUID doesn't work, we copy the binary instead.
RUN TCLSH_PATH=$(readlink -f $(which tclsh)) && \
    cp "$TCLSH_PATH" /usr/local/bin/oratclsh && \
    chown root:root /usr/local/bin/oratclsh && \
    chmod u+s /usr/local/bin/oratclsh

# Verify vulnerability is in place
RUN ls -la /usr/local/bin/oratclsh | grep -q "rws" && echo "SUID bit confirmed on oratclsh"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]