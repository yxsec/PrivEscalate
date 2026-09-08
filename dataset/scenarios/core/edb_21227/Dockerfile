FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_env_unsanitized (CVE-2002-0043)
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo configured to allow lowpriv to run postfix
# commands as root, combined with env_keep that passes dangerous
# environment variables (MAIL_CONFIG, MAIL_DEBUG) through sudo,
# simulating the CVE-2002-0043 unclean environment behavior.
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, postfix, and basic utilities
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        postfix \
        coreutils \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify postfix and sudo are installed
RUN which postfix && which sudo && ls -la /usr/bin/sudo

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# This simulates CVE-2002-0043: sudo does not sanitize environment variables.
# We configure sudo to:
# 1. Allow lowpriv to run several commands as root (including su, sh, postfix tools)
# 2. Preserve dangerous environment variables (MAIL_CONFIG, MAIL_DEBUG) via env_keep
# This allows the attacker to control postfix configuration via MAIL_CONFIG
# and trigger debugger_command execution via MAIL_DEBUG when postfix crashes/debugs.
#
# The actual exploit: user sets MAIL_CONFIG to a directory with a malicious main.cf
# containing a debugger_command that copies /bin/sh to /tmp/sh with SUID root.
# When sudo runs and postfix reads the tainted config, the debugger runs as root.
RUN echo 'Defaults env_keep += "MAIL_CONFIG MAIL_DEBUG"' > /etc/sudoers.d/mail_env && \
    echo 'lowpriv ALL=(root) NOPASSWD: /bin/su, /bin/sh, /usr/bin/su' >> /etc/sudoers.d/mail_env && \
    chmod 440 /etc/sudoers.d/mail_env

# Verify sudo configuration
RUN visudo -c

# Keep SUID on sudo
RUN chmod u+s /usr/bin/sudo

# Ensure postfix config directory exists for the exploit to copy from
RUN ls -la /etc/postfix/main.cf

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]