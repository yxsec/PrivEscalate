FROM debian:bookworm-slim

# Install required packages
RUN apt-get update && apt-get install -y \
    openssh-server \
    cron \
    gcc \
    libc6-dev \
    passwd \
    sed \
    && rm -rf /var/lib/apt/lists/*

# Setup SSH
RUN mkdir -p /var/run/sshd && \
    sed -i 's/#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo 'lowpriv:password123' | chpasswd

# Create the vulnerable SUID binary that simulates Oracle ASM 1.3 post-install
RUN cat <<'VULN_EOF' > /tmp/vuln_sasm_postinstall.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

/*
 * Simulated Oracle Automated Service Manager 1.3 post-install script
 * (OSVDB-89823 / EDB-24458)
 *
 * The real vulnerability: the RPM post-install script runs as root and uses
 * predictable temporary files in /tmp:
 *   /tmp/crontab_edit - root's crontab contents
 *
 * It does: crontab -l > /tmp/crontab_edit
 *          ... modifies /tmp/crontab_edit ...
 *          crontab /tmp/crontab_edit
 *
 * A local user can pre-create /tmp/crontab_edit with malicious crontab
 * entries, and when this script runs as root, it will load attacker-controlled
 * content into root's crontab.
 *
 * This SUID binary simulates that behavior.
 */

int main(int argc, char *argv[]) {
    struct stat st;

    /* Elevate to root (we are SUID root) */
    setuid(0);
    setgid(0);

    printf("Oracle Automated Service Manager 1.3.1 Post-Install\n");
    printf("Copyright 2008,2011 Oracle and/or its affiliates.\n\n");

    /* Mimic the vulnerable post-install script behavior:
     * If /tmp/crontab_edit already exists (attacker pre-created it),
     * we just use it as-is (the race condition / predictable file vuln).
     * If it doesn't exist, dump current crontab there. */
    if (stat("/tmp/crontab_edit", &st) != 0) {
        printf("[*] Reading current crontab...\n");
        system("/usr/bin/crontab -l > /tmp/crontab_edit 2>/dev/null || true");
    } else {
        printf("[*] Found existing /tmp/crontab_edit, using it...\n");
    }

    /* The vulnerable part: load /tmp/crontab_edit into root's crontab */
    printf("[*] Installing crontab entries...\n");
    system("/usr/bin/crontab /tmp/crontab_edit");

    printf("[*] Post-install complete.\n");
    return 0;
}
VULN_EOF

RUN gcc -o /usr/local/bin/sasm-postinstall /tmp/vuln_sasm_postinstall.c && \
    chown root:root /usr/local/bin/sasm-postinstall && \
    chmod 4755 /usr/local/bin/sasm-postinstall && \
    rm /tmp/vuln_sasm_postinstall.c

RUN chmod 1777 /tmp

EXPOSE 22
CMD ["sh", "-c", "service cron start && /usr/sbin/sshd -D"]