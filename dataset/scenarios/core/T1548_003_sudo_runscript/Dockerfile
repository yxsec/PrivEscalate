FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        openrc \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Create runscript symlink if needed
RUN if [ ! -f /usr/bin/runscript ]; then \
        if [ -f /sbin/openrc-run ]; then \
            ln -s /sbin/openrc-run /usr/bin/runscript; \
        elif [ -f /usr/sbin/openrc-run ]; then \
            ln -s /usr/sbin/openrc-run /usr/bin/runscript; \
        elif [ -f /sbin/runscript ]; then \
            ln -s /sbin/runscript /usr/bin/runscript; \
        else \
            echo "ERROR: Cannot find openrc-run or runscript" && exit 1; \
        fi; \
    fi

RUN ls -la /usr/bin/runscript

# Set up OpenRC environment so it doesn't complain
RUN mkdir -p /run/openrc && touch /run/openrc/softlevel

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Configure sudo vulnerability
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/runscript" > /etc/sudoers.d/runscript && \
    chmod 440 /etc/sudoers.d/runscript

RUN visudo -c

RUN chmod u+s /usr/bin/sudo

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/bin/bash", "-c", "mkdir -p /run/openrc && touch /run/openrc/softlevel && exec /usr/sbin/sshd -D"]