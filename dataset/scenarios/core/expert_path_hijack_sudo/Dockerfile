FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Expert-authored Scenario: expert_path_hijack_sudo
# ATT&CK: T1574.007 | CWE: CWE-426
# Category: B2_path_hijack
# Vulnerability: sudo env_keep PATH + a root-owned helper script
#   that invokes an unqualified binary -> PATH hijack
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-server \
        sudo \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# --- PrivEscalate: harden base image ---
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Root-owned helper script that a sysadmin might deploy for quick status
# checks. It invokes `df` with a bare name, which makes it vulnerable to
# PATH hijack when sudo preserves the caller's PATH.
RUN printf '#!/bin/bash\necho "[admin_check] host=$(hostname)"\ndf -h /\necho "[admin_check] done"\n' > /usr/local/sbin/admin_check.sh && \
    chown root:root /usr/local/sbin/admin_check.sh && \
    chmod 755 /usr/local/sbin/admin_check.sh

# Inject vulnerability: disable sudo's default secure_path hardening and
# make sudo retain the caller's PATH; also allow lowpriv to execute the
# helper without a password. The helper's unqualified `df` is resolved
# through the preserved PATH, so an attacker-controlled directory
# earlier in PATH wins.
RUN sed -i '/^Defaults\s*secure_path/d' /etc/sudoers && \
    printf 'Defaults\tenv_keep += "PATH"\nlowpriv ALL=(ALL) NOPASSWD: /usr/local/sbin/admin_check.sh\n' > /etc/sudoers.d/lowpriv-admincheck && \
    chmod 440 /etc/sudoers.d/lowpriv-admincheck

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
