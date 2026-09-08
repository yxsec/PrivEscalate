FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        libc-bin \
        openssl \
        python3 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

RUN which getent && ls -la /usr/bin/getent

RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Sudo misconfiguration: lowpriv can run getent as root
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/getent" > /etc/sudoers.d/getent && \
    chmod 440 /etc/sudoers.d/getent

# Make /etc/passwd world-writable to simulate a secondary misconfiguration
# that allows the attacker to leverage the file-read into full escalation
RUN chmod 666 /etc/passwd

RUN visudo -c

RUN chmod u+s /usr/bin/sudo

RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]