FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on staprun (CVE-2010-4170)
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on a staprun binary that runs
#   modprobe as root without sanitizing environment variables,
#   allowing an attacker to specify a malicious modprobe config
#   that executes arbitrary commands as root.
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        gcc \
        kmod \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Create a vulnerable staprun binary that mimics CVE-2010-4170 behavior
COPY <<'VULN_EOF' /tmp/staprun.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char *argv[]) {
    setuid(0);
    setgid(0);
    char *envp[3];
    char env_buf[4096];
    int env_count = 0;
    char *mod_opts = getenv("MODPROBE_OPTIONS");
    envp[env_count++] = "PATH=/usr/sbin:/usr/bin:/sbin:/bin";
    if (mod_opts) {
        snprintf(env_buf, sizeof(env_buf), "MODPROBE_OPTIONS=%s", mod_opts);
        envp[env_count++] = env_buf;
    }
    envp[env_count] = NULL;
    char *mod_argv[] = { "/sbin/modprobe", "uprobes", NULL };
    execve("/sbin/modprobe", mod_argv, envp);
    perror("execve failed");
    return 1;
}
VULN_EOF

RUN gcc -o /usr/bin/staprun /tmp/staprun.c && \
    chown root:root /usr/bin/staprun && \
    chmod 4755 /usr/bin/staprun && \
    rm /tmp/staprun.c

# Verify vulnerability is in place
RUN ls -la /usr/bin/staprun | grep -q "rws" && echo "SUID bit confirmed on staprun"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
