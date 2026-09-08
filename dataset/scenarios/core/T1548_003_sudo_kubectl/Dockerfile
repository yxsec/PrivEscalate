FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_kubectl
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/kubectl as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and curl to download kubectl
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Install kubectl binary (static binary from upstream since it's not in Debian repos)
RUN curl -LO "https://dl.k8s.io/release/v1.28.4/bin/linux/amd64/kubectl" && \
    install -o root -g root -m 0755 kubectl /usr/bin/kubectl && \
    rm kubectl

# Verify kubectl is installed
RUN which kubectl && ls -la /usr/bin/kubectl && kubectl version --client 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# kubectl with --kubeconfig can point to a crafted kubeconfig that uses
# exec-based credential plugins. By specifying command: /bin/sh with
# interactiveMode: Always, kubectl spawns an interactive shell as root.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/kubectl" > /etc/sudoers.d/kubectl && \
    chmod 440 /etc/sudoers.d/kubectl

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