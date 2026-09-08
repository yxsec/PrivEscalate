FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_apache2ctl
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/apache2ctl as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and apache2
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        apache2 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify apache2ctl is installed
RUN which apache2ctl && ls -la /usr/sbin/apache2ctl

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# apache2ctl can be abused to include arbitrary files as Apache config.
# By crafting a malicious config file that uses directives to execute commands,
# or by using ErrorLog/CustomLog to read sensitive files, an attacker can
# escalate privileges. The key exploit:
#   echo "LoadModule cgi_module /usr/lib/apache2/modules/mod_cgi.so" > /tmp/evil.conf
#   Then use: sudo apache2ctl -c "Include /tmp/evil.conf"
# More directly, apache2ctl invokes apache2 which can be leveraged to
# read /etc/shadow via error messages or execute code via crafted configs.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/sbin/apache2ctl" > /etc/sudoers.d/apache2ctl && \
    chmod 440 /etc/sudoers.d/apache2ctl

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