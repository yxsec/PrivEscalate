FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        python3 \
        python3-pip \
        python3-venv \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

RUN pip3 install --break-system-packages awsebcli && \
    ln -sf /usr/local/bin/eb /usr/bin/eb

RUN which eb && eb --version || true

RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Configure sudo vulnerability - allow eb as root with PYTHONPATH kept
RUN echo 'Defaults!/usr/bin/eb env_keep += "PYTHONPATH"' > /etc/sudoers.d/eb && \
    echo 'lowpriv ALL=(root) NOPASSWD: /usr/bin/eb' >> /etc/sudoers.d/eb && \
    chmod 440 /etc/sudoers.d/eb

RUN visudo -c

RUN chmod u+s /usr/bin/sudo

RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
