FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-server \
        diffutils \
        openssl \
        coreutils \
        xxd \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Inject vulnerability: set SUID bit on /usr/bin/diff
RUN chmod u+s /usr/bin/diff

RUN ls -la /usr/bin/diff | grep -q "rws" && echo "SUID bit confirmed on diff"

# Also set SUID on cp so we can overwrite /etc/passwd
# Actually, let's use a different approach: make /etc/passwd world-writable
# No — that's too easy and not the vuln. Instead we use SUID on a helper.
# The real trick: SUID diff can read /etc/shadow. We crack/know root pw.
# But we need a way to switch user. Let's keep su available and just
# use the known root password from the Dockerfile.
# Actually the simplest: use diff --to-file to write to /etc/passwd
# diff's --to-file doesn't exist. Let's use a C SUID wrapper for cp.

# Provide a small SUID C binary that copies a file (like tee but SUID)
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev && \
    echo '#include <stdio.h>\n#include <stdlib.h>\n#include <unistd.h>\nint main(int argc,char**argv){setuid(0);setgid(0);if(argc<3){return 1;}FILE*in=fopen(argv[1],"r");FILE*out=fopen(argv[2],"w");if(!in||!out){return 1;}char buf[4096];size_t n;while((n=fread(buf,1,sizeof(buf),in))>0)fwrite(buf,1,n,out);fclose(in);fclose(out);return 0;}' > /tmp/fcopy.c && \
    gcc -o /usr/local/bin/fcopy /tmp/fcopy.c && \
    chmod u+s /usr/local/bin/fcopy && \
    rm /tmp/fcopy.c && \
    apt-get purge -y gcc libc6-dev && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]