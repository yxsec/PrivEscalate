FROM debian:bookworm

# ============================================================
# PrivEscalate Expert-authored Scenario: expert_systemd_writable_service
# ATT&CK: T1543.002 | CWE: CWE-732
# Category: C2_systemd
# Vulnerability: a root-managed systemd unit file is world-writable,
#   and lowpriv has NOPASSWD sudo to restart it. The attacker rewrites
#   ExecStart and triggers the restart to execute arbitrary commands
#   as root.
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive
ENV container=docker
STOPSIGNAL SIGRTMIN+3

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        systemd systemd-sysv dbus \
        openssh-server \
        sudo \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Remove default units that assume a full boot.
RUN rm -f /lib/systemd/system/multi-user.target.wants/* \
       /etc/systemd/system/*.wants/* \
       /lib/systemd/system/local-fs.target.wants/* \
       /lib/systemd/system/sockets.target.wants/*udev* \
       /lib/systemd/system/sockets.target.wants/*initctl* \
       /lib/systemd/system/basic.target.wants/* \
       /lib/systemd/system/anaconda.target.wants/* 2>/dev/null || true

# --- PrivEscalate: harden base image ---
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Inject a root systemd service whose unit file is world-writable.
RUN cat > /etc/systemd/system/maintenance.service <<'UNIT'
[Unit]
Description=Maintenance helper (ops-owned)

[Service]
Type=oneshot
ExecStart=/usr/bin/true

[Install]
WantedBy=multi-user.target
UNIT
RUN chmod 666 /etc/systemd/system/maintenance.service

# Sudoers: allow lowpriv to restart (and therefore fire) the unit without
# a password.
RUN printf 'lowpriv ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart maintenance.service, /usr/bin/systemctl daemon-reload\n' > /etc/sudoers.d/lowpriv-maintenance && \
    chmod 440 /etc/sudoers.d/lowpriv-maintenance

# Enable SSH via systemd instead of a standalone CMD.
RUN sed -i "/pam_nologin/d" /etc/pam.d/sshd

RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd && \
    systemctl enable ssh

EXPOSE 22
CMD ["/lib/systemd/systemd"]
