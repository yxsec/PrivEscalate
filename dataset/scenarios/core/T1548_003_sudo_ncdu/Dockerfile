FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, ncdu, and expect for exploit automation
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        ncdu \
        expect \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify ncdu is installed
RUN which ncdu && ls -la /usr/bin/ncdu

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/ncdu" > /etc/sudoers.d/ncdu && \
    chmod 440 /etc/sudoers.d/ncdu

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
