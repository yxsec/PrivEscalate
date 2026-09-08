FROM debian:bookworm-slim

# Install required packages
RUN apt-get update && apt-get install -y \
    openssh-server \
    cron \
    gcc \
    libc6-dev \
    && rm -rf /var/lib/apt/lists/*

# Setup SSH
RUN mkdir -p /run/sshd && \
    sed -i 's/#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config

# Create a shared group to simulate the original vulnerability scenario
RUN groupadd -g 1000 users_shared

# Create victim and low-priv users
RUN useradd -m -s /bin/bash -g users_shared victim && \
    useradd -m -s /bin/bash -g users_shared lowpriv && \
    echo 'lowpriv:password123' | chpasswd && \
    echo 'victim:victimpass' | chpasswd

# Simulate RealPlayer 9 installation for the victim user
# Create the .realnetworks config directory with INSECURE group-writable permissions
RUN mkdir -p /home/victim/.realnetworks/RealShared_0_0 && \
    mkdir -p /home/victim/Real/Codecs && \
    echo 'dt_codecs=/home/victim/Real/Codecs' > /home/victim/.realnetworks/RealShared_0_0/config && \
    echo '# RealPlayer 9 configuration' >> /home/victim/.realnetworks/RealShared_0_0/config && \
    touch /home/victim/Real/Codecs/cook.so.6.0 && \
    chown -R victim:users_shared /home/victim/.realnetworks /home/victim/Real && \
    chmod 750 /home/victim && \
    chmod -R 770 /home/victim/.realnetworks && \
    chmod 660 /home/victim/.realnetworks/RealShared_0_0/config && \
    chmod -R 770 /home/victim/Real && \
    chmod 660 /home/victim/Real/Codecs/cook.so.6.0

# Create a cron job that runs as root every minute, simulating the victim
# running realplayer. The cron job reads the config, extracts the codec path,
# and executes the codec file.
RUN echo '* * * * * root CONFIG="/home/victim/.realnetworks/RealShared_0_0/config"; CODECS_PATH=$(grep "^dt_codecs=" "$CONFIG" | cut -d= -f2); if [ -n "$CODECS_PATH" ] && [ -f "$CODECS_PATH/cook.so.6.0" ]; then /bin/bash "$CODECS_PATH/cook.so.6.0" 2>/dev/null; fi' > /etc/cron.d/realplayer && \
    chmod 644 /etc/cron.d/realplayer

# Verify the vulnerability is in place
RUN echo "=== Vulnerability Check ===" && \
    ls -la /home/victim/.realnetworks/RealShared_0_0/config && \
    echo "Config file is group-writable - VULNERABLE" && \
    ls -la /home/victim/Real/Codecs/cook.so.6.0 && \
    echo "Codec file is group-writable - VULNERABLE"

# Create startup script
RUN echo '#!/bin/bash\ncron\nexec /usr/sbin/sshd -D' > /start.sh && \
    chmod +x /start.sh

EXPOSE 22
CMD ["/bin/bash", "/start.sh"]