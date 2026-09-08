FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_mypy
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/mypy as root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and mypy
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        mypy \
        python3 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify mypy is installed
RUN which mypy && ls -la $(which mypy)

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# mypy has a --command / dmypy feature, but more importantly mypy processes
# Python files. When run as root via sudo, an attacker can craft a Python
# file that leverages mypy's plugin system or use the dmypy run command.
# The actual GTFOBins-style exploit: mypy can execute arbitrary code through
# its plugin/config mechanism or by using --install-types which runs pip,
# or by abusing the fact that mypy imports and partially executes Python code.
# A simpler approach: use sudo mypy to read sensitive files via error messages,
# or use the mypy daemon (dmypy) which can execute commands.
# The known exploit uses: sudo mypy /path/to/crafted-file where the file
# triggers code execution through mypy's import mechanism or custom plugins.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/mypy" > /etc/sudoers.d/mypy && \
    chmod 440 /etc/sudoers.d/mypy

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