FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_mysql
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/mysql as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and MariaDB server+client
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        mariadb-server \
        mariadb-client \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd /run/mysqld \
    && chown mysql:mysql /run/mysqld

# Initialize MariaDB data directory
RUN mysql_install_db --user=mysql --datadir=/var/lib/mysql 2>/dev/null || true

# Verify mysql client is installed
RUN which mysql && ls -la /usr/bin/mysql

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/mysql" > /etc/sudoers.d/mysql && \
    chmod 440 /etc/sudoers.d/mysql

# Verify sudo configuration
RUN visudo -c

# Keep SUID on sudo
RUN chmod u+s /usr/bin/sudo

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

# Create a startup script that starts both MariaDB and SSH
RUN echo '#!/bin/bash\nmysqld_safe --skip-grant-tables &\nsleep 2\nexec /usr/sbin/sshd -D' > /start.sh && \
    chmod +x /start.sh

EXPOSE 22
CMD ["/start.sh"]
