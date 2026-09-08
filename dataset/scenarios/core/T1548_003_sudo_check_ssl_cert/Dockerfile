FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        monitoring-plugins-basic \
        nagios-plugins-contrib \
        curl \
        openssl \
        bc \
        file \
        bind9-dnsutils \
        coreutils \
        nmap \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

RUN if [ ! -f /usr/bin/check_ssl_cert ]; then \
        if [ -f /usr/lib/nagios/plugins/check_ssl_cert ]; then \
            ln -s /usr/lib/nagios/plugins/check_ssl_cert /usr/bin/check_ssl_cert; \
        fi; \
    fi

RUN if [ ! -f /usr/bin/check_ssl_cert ] && [ ! -f /usr/lib/nagios/plugins/check_ssl_cert ]; then \
        apt-get update && apt-get install -y wget && \
        wget -O /usr/bin/check_ssl_cert https://raw.githubusercontent.com/matteocorti/check_ssl_cert/v2.80.0/check_ssl_cert && \
        chmod +x /usr/bin/check_ssl_cert && \
        rm -rf /var/lib/apt/lists/*; \
    fi

RUN ls -la /usr/bin/check_ssl_cert || ls -la /usr/lib/nagios/plugins/check_ssl_cert

RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Configure sudo vulnerability - allow check_ssl_cert as root
RUN CHECK_SSL_PATH=$(readlink -f /usr/bin/check_ssl_cert 2>/dev/null || echo "/usr/bin/check_ssl_cert") && \
    echo "lowpriv ALL=(root) NOPASSWD: $CHECK_SSL_PATH" > /etc/sudoers.d/check_ssl_cert && \
    if [ "$CHECK_SSL_PATH" != "/usr/bin/check_ssl_cert" ]; then \
        echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/check_ssl_cert" >> /etc/sudoers.d/check_ssl_cert; \
    fi && \
    chmod 440 /etc/sudoers.d/check_ssl_cert

RUN visudo -c

RUN chmod u+s /usr/bin/sudo

RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]