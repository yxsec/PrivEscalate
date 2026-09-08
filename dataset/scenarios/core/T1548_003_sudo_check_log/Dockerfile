FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        less \
        python3 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

RUN printf '#!/bin/bash\n/usr/bin/less /var/log/syslog\n' > /usr/bin/check_log && \
    chmod 755 /usr/bin/check_log

RUN touch /var/log/syslog && \
    echo "System log initialized" > /var/log/syslog

RUN ls -la /usr/bin/check_log && cat /usr/bin/check_log

RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/check_log" > /etc/sudoers.d/check_log && \
    chmod 440 /etc/sudoers.d/check_log

RUN visudo -c

RUN chmod u+s /usr/bin/sudo

RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
