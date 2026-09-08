FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_tailscale
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/tailscale as root
# The tailscale binary is actually a wrapper that can execute arbitrary commands
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and dependencies
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        gcc \
        openssl \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Create a fake "tailscale" binary that mimics a vulnerable tool
COPY <<'CEOF' /tmp/tailscale.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("tailscale - simulated CLI\n");
        printf("Usage: tailscale <subcommand> [args...]\n");
        return 0;
    }
    if (strcmp(argv[1], "debug") == 0 && argc >= 3 && strcmp(argv[2], "run") == 0) {
        if (argc >= 4) {
            execvp(argv[3], &argv[3]);
            perror("exec failed");
            return 1;
        }
    }
    if (strcmp(argv[1], "version") == 0) {
        printf("1.96.4\n");
        return 0;
    }
    if (strcmp(argv[1], "file") == 0 && argc >= 3 && strcmp(argv[2], "cp") == 0) {
        if (argc == 5) {
            char cmd[4096];
            snprintf(cmd, sizeof(cmd), "cp '%s' '%s'", argv[3], argv[4]);
            return system(cmd);
        }
    }
    printf("tailscale: unknown or incomplete command\n");
    return 1;
}
CEOF

RUN gcc -o /usr/bin/tailscale /tmp/tailscale.c && \
    rm /tmp/tailscale.c && \
    chmod 755 /usr/bin/tailscale

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/tailscale" > /etc/sudoers.d/tailscale && \
    chmod 440 /etc/sudoers.d/tailscale

# Verify sudo configuration
RUN visudo -c

# Keep SUID on sudo
RUN chmod u+s /usr/bin/sudo

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
