FROM debian:bookworm-slim

# Install required packages
RUN apt-get update && apt-get install -y \
    openssh-server \
    cron \
    net-tools \
    wget \
    build-essential \
    passwd \
    && rm -rf /var/lib/apt/lists/*

# Setup SSH
RUN mkdir -p /var/run/sshd && \
    sed -i 's/#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo 'lowpriv:password123' | chpasswd

# Create vulnerable chkrootkit 0.49 script
RUN mkdir -p /usr/local/chkrootkit && \
    printf '#!/bin/bash\n\
ROOTDIR="/"\n\
SYSTEM="Linux"\n\
QUIET=""\n\
NOT_INFECTED=0\n\
netstat=$(which netstat 2>/dev/null || echo "netstat")\n\
egrep=$(which egrep 2>/dev/null || echo "egrep")\n\
awk=$(which awk 2>/dev/null || echo "awk")\n\
slapper () {\n\
   SLAPPER_FILES="${ROOTDIR}tmp/.bugtraq ${ROOTDIR}tmp/.bugtraq.c"\n\
   SLAPPER_FILES="$SLAPPER_FILES ${ROOTDIR}tmp/.unlock ${ROOTDIR}tmp/httpd \\\n\
   ${ROOTDIR}tmp/update ${ROOTDIR}tmp/.cinik ${ROOTDIR}tmp/.b"\n\
   SLAPPER_PORT="0.0:2002 |0.0:4156 |0.0:1978 |0.0:1812 |0.0:2015 "\n\
   OPT=-an\n\
   STATUS=0\n\
   file_port=\n\
   for i in ${SLAPPER_FILES}; do\n\
      if [ -f ${i} ]; then\n\
         file_port=$file_port $i\n\
         STATUS=1\n\
      fi\n\
   done\n\
   if [ ${STATUS} -eq 1 ] ;then\n\
      echo "Warning: Possible Slapper Worm installed ($file_port)"\n\
   else\n\
      if [ "${QUIET}" != "t" ]; then echo "not infected"; fi\n\
         return ${NOT_INFECTED}\n\
   fi\n\
}\n\
echo "ROOTDIR is \`${ROOTDIR}\x27"\n\
echo "Checking \`slapper\x27..."\n\
slapper\n\
echo "chkrootkit scan complete."\n' > /usr/local/chkrootkit/chkrootkit && \
    chmod 755 /usr/local/chkrootkit/chkrootkit && \
    ln -sf /usr/local/chkrootkit/chkrootkit /usr/local/bin/chkrootkit

# Set up a cron job to run chkrootkit as root every minute
RUN echo "* * * * * root /usr/local/bin/chkrootkit > /dev/null 2>&1" > /etc/cron.d/chkrootkit_check && \
    chmod 644 /etc/cron.d/chkrootkit_check

# Make /tmp world-writable
RUN chmod 1777 /tmp

# Expose SSH
EXPOSE 22

# Start cron and SSH
CMD service cron start && /usr/sbin/sshd -D
