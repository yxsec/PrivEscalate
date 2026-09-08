FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on tac
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on /usr/bin/tac allows
#   privilege escalation via reading sensitive files like
#   /etc/shadow (tac reads files in reverse line order)
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, openssl for password operations, and util-linux for su
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-server \
        coreutils \
        openssl \
        python3 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Set a known root password (weak, crackable via shadow read)
RUN echo "root:exploited" | chpasswd

# Inject vulnerability: set SUID bit on tac
RUN chmod u+s /usr/bin/tac

# Verify vulnerability is in place
RUN ls -la /usr/bin/tac | grep -q "rws" && echo "SUID bit confirmed on tac"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
