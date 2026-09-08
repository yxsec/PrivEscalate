FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_rsyslogd
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/rsyslogd as root
# rsyslogd can be used with a custom config to read arbitrary files
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and rsyslog
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        rsyslog \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify rsyslogd is installed
RUN which rsyslogd && ls -la /usr/sbin/rsyslogd

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# rsyslogd can be run with a custom config file (-f) that uses omprog or
# omfile to read/write arbitrary files. With a crafted config, an attacker
# can exfiltrate sensitive files like /etc/shadow.
#
# Exploit approach:
#   1. Create a custom rsyslog config that reads a target file
#   2. sudo rsyslogd -f /tmp/evil.conf -n
#   3. The config can use omfile/omprog to copy sensitive data to readable locations
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/sbin/rsyslogd" > /etc/sudoers.d/rsyslogd && \
    chmod 440 /etc/sudoers.d/rsyslogd

# Verify sudo configuration
RUN visudo -c

# Keep SUID on sudo
RUN chmod u+s /usr/bin/sudo

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]