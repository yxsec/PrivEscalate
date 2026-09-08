FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_terraform
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/terraform as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and dependencies
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        wget \
        unzip \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Install terraform binary (specific version for reproducibility).
# Detect architecture at build-time so arm64 hosts (e.g. Apple Silicon) get the right binary.
RUN ARCH=$(uname -m) && \
    case "$ARCH" in \
        x86_64|amd64) TF_ARCH=amd64 ;; \
        aarch64|arm64) TF_ARCH=arm64 ;; \
        *) echo "unsupported arch: $ARCH"; exit 1 ;; \
    esac && \
    wget -q "https://releases.hashicorp.com/terraform/1.5.7/terraform_1.5.7_linux_${TF_ARCH}.zip" -O /tmp/terraform.zip && \
    unzip /tmp/terraform.zip -d /usr/bin/ && \
    chmod 755 /usr/bin/terraform && \
    rm /tmp/terraform.zip

# Verify terraform is installed
RUN which terraform && ls -la /usr/bin/terraform && terraform version

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# terraform console allows reading arbitrary files via file() function:
#   sudo terraform console
#   file("/etc/shadow")
# Additionally, terraform can execute arbitrary commands through provisioners
# or by abusing the console's file() to read sensitive credentials.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/terraform" > /etc/sudoers.d/terraform && \
    chmod 440 /etc/sudoers.d/terraform

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