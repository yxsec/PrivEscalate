FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        python3 \
        procps \
        gcc \
        libc6-dev \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Create a stub 'code' binary that supports:
#   --export FILE  -> prints file contents to stdout (file read as root)
#   --import FILE  -> reads stdin and writes to FILE (file write as root)
# This simulates the GTFOBins code escalation paths.
RUN printf '#!/usr/bin/python3\nimport sys, os, argparse\np = argparse.ArgumentParser()\np.add_argument("--export", default=None)\np.add_argument("--import-to", dest="import_to", default=None)\np.add_argument("args", nargs="*")\na = p.parse_args()\nif a.export:\n    with open(a.export, "rb") as f:\n        sys.stdout.buffer.write(f.read())\nelif a.import_to:\n    data = sys.stdin.buffer.read()\n    with open(a.import_to, "wb") as f:\n        f.write(data)\nelse:\n    print("Usage: code --export FILE or code --import-to FILE")\n' > /usr/bin/code && \
    chmod 755 /usr/bin/code

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Vulnerable sudo configuration: lowpriv can run /usr/bin/code as root
RUN echo 'lowpriv ALL=(root) NOPASSWD: /usr/bin/code' > /etc/sudoers.d/code && \
    chmod 440 /etc/sudoers.d/code && \
    visudo -c

# Keep SUID on sudo
RUN chmod u+s /usr/bin/sudo

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
