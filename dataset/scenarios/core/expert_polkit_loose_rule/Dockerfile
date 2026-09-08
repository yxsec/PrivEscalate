FROM debian:bookworm

# ============================================================
# PrivEscalate Expert-authored Scenario: expert_polkit_loose_rule
# ATT&CK: T1548 | CWE: CWE-269
# Category: A4_polkit
# Vulnerability: a polkit .rules file grants lowpriv unconditional YES
#   on all actions. Combined with pkexec (SUID root), lowpriv runs any
#   command as root without authentication.
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive
ENV container=docker
STOPSIGNAL SIGRTMIN+3

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        systemd systemd-sysv dbus \
        policykit-1 \
        openssh-server \
        sudo \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

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

# Inject vulnerability: a loose polkit rule that grants YES to lowpriv
# on every action. pkexec is SUID root, so lowpriv can pkexec arbitrary
# commands without credentials.
RUN mkdir -p /etc/polkit-1/rules.d && \
    cat > /etc/polkit-1/rules.d/99-lowpriv-loose.rules <<'POLKIT'
polkit.addRule(function(action, subject) {
    if (subject.user == "lowpriv") {
        return polkit.Result.YES;
    }
});
POLKIT

RUN sed -i "/pam_nologin/d" /etc/pam.d/sshd

RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd && \
    systemctl enable ssh polkit

EXPOSE 22
CMD ["/lib/systemd/systemd"]
