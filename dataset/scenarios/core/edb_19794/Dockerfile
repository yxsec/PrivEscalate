FROM debian:bookworm-slim

# Install required packages
RUN apt-get update && apt-get install -y \
    openssh-server \
    cron \
    && rm -rf /var/lib/apt/lists/*

# Setup SSH
RUN mkdir -p /run/sshd && \
    sed -i 's/#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo 'lowpriv:password123' | chpasswd

# Simulate the Oracle 8.1.5i installer vulnerability (CVE-2000-0206):
# The Oracle installer creates /tmp/orainstall (mode 711) and places
# orainstRoot.sh (mode 777) inside it, then asks root to run it.
# Since the script is world-writable, any user can modify it before
# root executes it, leading to arbitrary command execution as root.
#
# We simulate this with:
# 1. A world-writable script in /tmp/orainstall/ (the vulnerable artifact)
# 2. A cron job that periodically runs the script as root (simulating the
#    installer asking root to execute orainstRoot.sh)

RUN mkdir -p /tmp/orainstall && \
    chmod 711 /tmp/orainstall && \
    echo '#!/bin/bash' > /tmp/orainstall/orainstRoot.sh && \
    echo '# Oracle post-install root script' >> /tmp/orainstall/orainstRoot.sh && \
    echo 'echo "Oracle post-install completed"' >> /tmp/orainstall/orainstRoot.sh && \
    chmod 777 /tmp/orainstall/orainstRoot.sh

# Create a cron job that simulates root running the Oracle installer script
# every minute (simulating the installer prompt "Please run orainstRoot.sh as root")
RUN echo '* * * * * root /bin/bash /tmp/orainstall/orainstRoot.sh >> /tmp/orainstall.log 2>&1' > /etc/cron.d/oracle-installer && \
    chmod 644 /etc/cron.d/oracle-installer

# Verify the vulnerability is in place
RUN ls -la /tmp/orainstall/orainstRoot.sh && \
    echo "orainstRoot.sh is world-writable (mode 777) - VULNERABLE"

# Create startup script
RUN echo '#!/bin/bash\ncron\nexec /usr/sbin/sshd -D' > /start.sh && \
    chmod +x /start.sh

EXPOSE 22
CMD ["/bin/bash", "/start.sh"]