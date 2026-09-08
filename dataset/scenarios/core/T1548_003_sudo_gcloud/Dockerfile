FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_gcloud
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/gcloud as root
# GTFOBins: gcloud can be exploited via CLOUDSDK_PYTHON and env_keep
# or by using its built-in shell functionality
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, python3, and create a fake gcloud binary
# gcloud (Google Cloud SDK) is not in Debian repos, so we install the SDK manually
# or create a functional equivalent. The GTFOBins exploit for gcloud works because
# gcloud is a Python wrapper that respects CLOUDSDK_PYTHON env var or allows
# running arbitrary commands through its config/shell features.
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        python3 \
        curl \
        bash \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Install Google Cloud SDK to get a real /usr/bin/gcloud
# We install it to /usr/lib/google-cloud-sdk and symlink gcloud
RUN curl -sSL https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-cli-linux-x86_64.tar.gz | \
    tar -xz -C /usr/lib/ && \
    ln -sf /usr/lib/google-cloud-sdk/bin/gcloud /usr/bin/gcloud

# Verify gcloud is installed
RUN which gcloud && ls -la /usr/bin/gcloud

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# The GTFOBins exploit for gcloud:
#   sudo gcloud help
# gcloud invokes a pager (less/man) which can be escaped to a shell with !/bin/sh
# Alternatively, CLOUDSDK_PYTHON can be set to execute arbitrary code.
# We allow env_keep for CLOUDSDK_PYTHON so the user can control which Python
# interpreter gcloud uses, enabling:
#   CLOUDSDK_PYTHON=/bin/bash sudo gcloud help
# or using the pager escape.
RUN echo 'Defaults!/usr/bin/gcloud env_keep += "CLOUDSDK_PYTHON CLOUDSDK_PYTHON_ARGS"' > /etc/sudoers.d/gcloud && \
    echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/gcloud" >> /etc/sudoers.d/gcloud && \
    chmod 440 /etc/sudoers.d/gcloud

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