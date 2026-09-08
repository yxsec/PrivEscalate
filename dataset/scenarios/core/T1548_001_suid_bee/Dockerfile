FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        nodejs \
        gcc \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Create the Node.js bee script (the actual logic)
RUN printf '#!/usr/bin/env node\nconst args = process.argv.slice(2);\nif (args[0] === "-e" && args[1]) {\n  eval(args[1]);\n} else if (args.length > 0) {\n  require(require("path").resolve(args[0]));\n} else {\n  require("repl").start("> ");\n}\n' > /usr/lib/bee.js && \
    chmod 755 /usr/lib/bee.js

# Create a compiled C SUID wrapper that execs node with the bee script
# This preserves effective UID across exec since it's a compiled binary
RUN printf '#include <stdio.h>\n#include <stdlib.h>\n#include <unistd.h>\nint main(int argc, char *argv[]) {\n    setuid(0);\n    setgid(0);\n    char *new_argv[argc + 2];\n    new_argv[0] = "node";\n    new_argv[1] = "/usr/lib/bee.js";\n    for (int i = 1; i < argc; i++) {\n        new_argv[i + 1] = argv[i];\n    }\n    new_argv[argc + 1] = NULL;\n    execvp("node", new_argv);\n    perror("execvp");\n    return 1;\n}\n' > /tmp/bee_wrapper.c && \
    gcc -o /usr/bin/bee /tmp/bee_wrapper.c && \
    rm /tmp/bee_wrapper.c

# Harden base image
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Inject vulnerability: set SUID bit on bee
RUN chown root:root /usr/bin/bee && \
    chmod u+s /usr/bin/bee

# Verify vulnerability is in place
RUN ls -la /usr/bin/bee | grep -q "rws" && echo "SUID bit confirmed on bee"

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
