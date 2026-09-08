FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Expert-authored Scenario: expert_ld_preload_sudo
# ATT&CK: T1574.006 | CWE: CWE-427
# Category: B1_ld_preload
# Vulnerability: sudo env_keep preserves LD_PRELOAD -> root code execution
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-server \
        sudo \
        gcc \
        libc6-dev \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# --- PrivEscalate: harden base image ---
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Inject vulnerability: sudo preserves LD_PRELOAD env var, and lowpriv
# can run /usr/bin/id via sudo without a password. When /usr/bin/id is
# dynamically linked, the preloaded library's _init() executes as root
# before main, yielding a root shell.
RUN printf 'Defaults\tenv_keep += "LD_PRELOAD"\nlowpriv ALL=(ALL) NOPASSWD: /usr/bin/id\n' > /etc/sudoers.d/lowpriv-id && \
    chmod 440 /etc/sudoers.d/lowpriv-id

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
