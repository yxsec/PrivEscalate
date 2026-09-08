FROM debian:bookworm

# ============================================================
# PrivEscalate Expert-authored Scenario: expert_dbus_loose_policy
# ATT&CK: T1068 | CWE: CWE-269
# Category: A5_dbus
# Vulnerability: a custom system-bus D-Bus service ("com.example.Executor")
#   runs as root and exposes a Run(command) method. Its D-Bus policy
#   unconditionally allows lowpriv to invoke the method, so any
#   dbus-send from lowpriv executes a command as root.
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive
ENV container=docker
STOPSIGNAL SIGRTMIN+3

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        systemd systemd-sysv dbus \
        python3 python3-dbus python3-gi \
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

# Install the vulnerable D-Bus service.
RUN cat > /usr/local/bin/executor-svc.py <<'PY'
#!/usr/bin/env python3
import os
import dbus
import dbus.service
import dbus.mainloop.glib
from gi.repository import GLib

BUS_NAME = "com.example.Executor"
OBJ_PATH = "/com/example/Executor"
IFACE    = "com.example.Executor.Admin"

class Executor(dbus.service.Object):
    @dbus.service.method(IFACE, in_signature='s', out_signature='s')
    def Run(self, cmd):
        os.system(cmd)
        return "ok"

if __name__ == "__main__":
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    # Keep explicit references so the Python GC does not release the
    # BusName before the main loop starts.
    name = dbus.service.BusName(BUS_NAME, bus=bus, do_not_queue=True)
    obj = Executor(bus, OBJ_PATH)
    GLib.MainLoop().run()
PY
RUN chmod 755 /usr/local/bin/executor-svc.py

# Systemd unit so the service runs as root on boot.
RUN cat > /etc/systemd/system/executor-svc.service <<'UNIT'
[Unit]
Description=Vulnerable Executor D-Bus Service
After=dbus.service
Requires=dbus.service

[Service]
Type=simple
ExecStart=/usr/local/bin/executor-svc.py
Restart=on-failure

[Install]
WantedBy=multi-user.target
UNIT

# Inject vulnerability: D-Bus policy grants lowpriv unrestricted access
# to invoke methods on com.example.Executor.
RUN cat > /etc/dbus-1/system.d/com.example.Executor.conf <<'XML'
<!DOCTYPE busconfig PUBLIC
 "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <policy user="root">
    <allow own="com.example.Executor"/>
    <allow send_destination="com.example.Executor"/>
  </policy>
  <policy user="lowpriv">
    <allow send_destination="com.example.Executor"/>
    <allow send_interface="com.example.Executor.Admin"/>
  </policy>
</busconfig>
XML

RUN sed -i "/pam_nologin/d" /etc/pam.d/sshd

RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd && \
    systemctl enable ssh executor-svc

EXPOSE 22
CMD ["/lib/systemd/systemd"]
