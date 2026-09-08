FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        npm \
        nodejs \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Install pyright globally via npm
RUN npm install -g pyright

# Verify pyright is installed and find its path
RUN which pyright && ls -la $(which pyright)

# Create a symlink at /usr/bin/pyright if it's not already there
RUN ln -sf $(which pyright) /usr/bin/pyright 2>/dev/null || true
RUN ls -la /usr/bin/pyright

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Configure sudo vulnerability: allow pyright as root with NODE_OPTIONS preserved
RUN echo 'Defaults env_keep += "NODE_OPTIONS"' > /etc/sudoers.d/pyright && \
    echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/pyright" >> /etc/sudoers.d/pyright && \
    chmod 440 /etc/sudoers.d/pyright

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
