FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: ptrace Sudo Token Privilege Escalation
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: User has sudo ALL access + gdb installed + ptrace enabled
# The attacker can use gdb to ptrace their own shell processes and
# inject system() calls. Combined with cached sudo tokens (or in this
# scenario, passwordless sudo), this achieves root.
# The core vulnerability: sudo NOPASSWD ALL + gdb + ptrace permitted
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, gdb (with python support), procps for ps
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        gdb \
        procps \
        bash \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify gdb is installed
RUN which gdb && gdb --version | head -1

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure the vulnerability ---
# The exploit relies on:
# 1. gdb being available to perform ptrace injection
# 2. sudo tokens being cached (or sudo being available without password)
# 3. ptrace_scope being permissive (0)
#
# We grant lowpriv sudo ALL with NOPASSWD to simulate cached sudo tokens.
# The attacker uses gdb to attach to a process and call system() to
# execute commands as root via the sudo token.
RUN echo "lowpriv ALL=(root) NOPASSWD: ALL" > /etc/sudoers.d/lowpriv && \
    chmod 440 /etc/sudoers.d/lowpriv

# Ensure ptrace is permissive (set at runtime via sysctl if possible,
# but also create a script that the scenario documents)
# In Docker, ptrace_scope is inherited from host; we document the requirement
# Container should be run with --cap-add=SYS_PTRACE or --security-opt seccomp=unconfined

# Verify sudo configuration
RUN visudo -c

# Keep SUID on sudo
RUN chmod u+s /usr/bin/sudo

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

# Verify the vulnerability components are in place
RUN echo "=== Vulnerability Check ===" && \
    which gdb && \
    cat /etc/sudoers.d/lowpriv && \
    echo "=== gdb + sudo NOPASSWD ALL + ptrace = root ==="

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]