FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on /bin/su (CVE-2000-0844 style)
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on /bin/su allows privilege
#   escalation. While CVE-2000-0844 was a glibc format string
#   bug in locale handling affecting SUID /bin/su on old systems,
#   we simulate the core attack surface: SUID /bin/su combined
#   with a known root password enabling direct escalation.
#   The attacker uses: /bin/su -c 'id' root
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, build tools, and utilities the exploit references
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        login \
        util-linux \
        gcc \
        binutils \
        gettext \
        locales \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Generate some locales (exploit uses LC_MESSAGES manipulation)
RUN sed -i 's/^# *en_US.UTF-8/en_US.UTF-8/' /etc/locale.gen && \
    locale-gen

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Inject vulnerability: Ensure SUID bit is set on /bin/su
# On modern Debian, su is in /bin/su (or /usr/bin/su via symlink)
# We ensure SUID is explicitly set, which is the core attack surface
RUN chmod u+s /bin/su 2>/dev/null || chmod u+s /usr/bin/su 2>/dev/null

# Set a weak/known root password that the lowpriv user can exploit via SUID su
RUN echo "root:root" | chpasswd

# Place the exploit source in the lowpriv user's home for reference
RUN echo '#!/bin/sh\n# CVE-2000-0844 style escalation via SUID /bin/su\n# With known root password, SUID su grants root shell:\nexec /bin/su -c "/bin/sh" root' > /home/lowpriv/exploit.sh && \
    chmod +x /home/lowpriv/exploit.sh && \
    chown lowpriv:lowpriv /home/lowpriv/exploit.sh

# Verify vulnerability is in place
RUN ls -la /bin/su | grep -q "rws" && echo "SUID bit confirmed on /bin/su" || \
    (ls -la /usr/bin/su | grep -q "rws" && echo "SUID bit confirmed on /usr/bin/su")

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]