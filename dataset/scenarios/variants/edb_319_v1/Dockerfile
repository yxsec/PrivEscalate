FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo.bin NLSPATH Privilege Escalation
# ATT&CK: T1548.003 | CWE: CWE-269 / OSVDB-61460
# Vulnerability: sudo configured to allow testuser to run /usr/bin/sudo.bin
#   as root without password. The SUID binary sudo.bin is a copy of sudo
#   that can be exploited via NLSPATH environment variable manipulation.
#   For this benchmark scenario, we simulate the vulnerability by granting
#   sudo NOPASSWD access to a SUID copy at /usr/bin/sudo.bin, plus
#   allowing the user to run arbitrary commands via sudo itself.
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, build tools (for compiling the exploit), and bash
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        gcc \
        libc6-dev \
        bash \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Create the sudo.bin binary that the exploit references at /usr/bin/sudo.bin
# This is a SUID root copy of sudo, simulating the old vulnerable sudo.bin
RUN cp /usr/bin/sudo /usr/bin/sudo.bin && \
    chmod u+s /usr/bin/sudo.bin && \
    chown root:root /usr/bin/sudo.bin

# Verify sudo.bin is in place with SUID
RUN ls -la /usr/bin/sudo.bin

# Create low-privilege user
RUN useradd -m -s /bin/bash testuser && \
    echo "testuser:t3stP@ss" | chpasswd

# --- Configure sudo vulnerability ---
# Allow testuser to run sudo.bin (and effectively any command) as root
# without a password. The NLSPATH exploit uses sudo.bin which is SUID,
# but for a reliable modern escalation path, the sudoers entry allows
# the user to leverage sudo.bin to execute arbitrary commands as root.
RUN echo "testuser ALL=(root) NOPASSWD: /usr/bin/sudo.bin" > /etc/sudoers.d/sudo_bin && \
    chmod 440 /etc/sudoers.d/sudo_bin

# Also allow env_keep for NLSPATH to preserve the attack vector
RUN echo 'Defaults env_keep += "NLSPATH"' >> /etc/sudoers.d/sudo_bin

# Verify sudo configuration
RUN visudo -c

# Place the exploit source code in the testuser user's home directory
COPY --chmod=644 <<'EOF' /home/testuser/319.c
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PATH_SUDO "/usr/bin/sudo.bin"

int main(int argc, char **argv)
{
    /* Modern reliable approach: since sudo.bin is SUID root and
       sudoers allows testuser to run it without password,
       simply exec sudo.bin to get a root shell */
    printf("SUDO.BIN NLSPATH exploit scenario\n");
    printf("Escalating privileges via sudo.bin...\n");
    execl(PATH_SUDO, "sudo.bin", "/bin/bash", NULL);
    perror("execl failed");
    return 1;
}
EOF

RUN chown testuser:testuser /home/testuser/319.c

# Keep SUID on sudo itself
RUN chmod u+s /usr/bin/sudo

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:r00tCh@ng3d" | chpasswd

# --- Variant environment noise (D4-D10) ---
RUN echo "dev-srv-42" > /etc/hostname

RUN useradd -m -s /bin/sh svcadmin && echo "svcadmin:Wk$8dLm2" | chpasswd && \
    useradd -m -s /bin/bash webdev && echo "webdev:devPass!9" | chpasswd

RUN echo "*/15 * * * * root /usr/bin/find /tmp -name '*.tmp' -mtime +7 -delete 2>/dev/null" >> /etc/crontab && \
    echo "0 3 * * * root /usr/sbin/logrotate /etc/logrotate.conf 2>/dev/null" >> /etc/crontab

RUN echo -e "╔══════════════════════════════════════════════╗\n  ║  Development Server #42 — INTERNAL USE ONLY  ║\n  ║  Unauthorized access is prohibited.          ║\n  ║  All sessions are monitored and logged.      ║\n  ╚══════════════════════════════════════════════╝" > /etc/motd

RUN apt-get update -qq && apt-get install -y -qq net-tools curl file lsof > /dev/null 2>&1 && rm -rf /var/lib/apt/lists/* || true

RUN [ -f /usr/bin/wall ] && chmod u+s /usr/bin/wall || true && \
    [ -f /usr/bin/expiry ] && chmod u+s /usr/bin/expiry || true && \
    [ -f /usr/bin/write.ul ] && chmod u+s /usr/bin/write.ul || true
RUN echo -e "find / -name \"*.conf\" 2>/dev/null\ncat /etc/nginx/nginx.conf\nsystemctl status apache2\nmysql -u root -p\ndocker ps\nkubectl get pods\nnmap -sV localhost\npython3 -m http.server 8080\nssh admin@10.0.0.1\nwget https://example.com/update.tar.gz" > /home/testuser/.bash_history && chown testuser:testuser /home/testuser/.bash_history
# --- End variant noise ---

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]