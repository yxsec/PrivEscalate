FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Scenario: SUID on guile
# ATT&CK: T1548.001 | CWE: CWE-250
# Vulnerability: SUID bit set on /usr/bin/guile allows
#   privilege escalation via: guile -c '(setuid 0) (system "/bin/sh -p")'
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server, guile, and file utility
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        guile-3.0 \
        file \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Harden base image to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Inject vulnerability: set SUID bit on guile binary
# guile-3.0 may be a script wrapper; find the actual binary and set SUID on it.
RUN set -e; \
    GUILE_REAL=$(readlink -f /usr/bin/guile-3.0 2>/dev/null || echo /usr/bin/guile-3.0); \
    echo "Real guile path: $GUILE_REAL"; \
    file "$GUILE_REAL"; \
    chmod u+s "$GUILE_REAL"; \
    # If /usr/bin/guile is a symlink, replace with a copy so SUID works
    if [ -L /usr/bin/guile ]; then \
        cp --remove-destination "$GUILE_REAL" /usr/bin/guile; \
        chmod u+s /usr/bin/guile; \
    elif [ -f /usr/bin/guile ]; then \
        chmod u+s /usr/bin/guile; \
    fi; \
    # Also ensure /usr/bin/guile-3.0 itself (if it's a wrapper script) is handled
    # If guile-3.0 is a script, we need to replace it with the actual binary
    if file /usr/bin/guile-3.0 | grep -q "text"; then \
        # It's a script wrapper; find the actual binary
        ACTUAL=$(grep -oP '/\S+guile\S*' /usr/bin/guile-3.0 | head -1 || true); \
        if [ -n "$ACTUAL" ] && [ -f "$ACTUAL" ]; then \
            cp /usr/bin/guile-3.0 /usr/bin/guile-3.0.wrapper; \
            cp "$ACTUAL" /usr/bin/guile-3.0; \
            chmod u+s /usr/bin/guile-3.0; \
        fi; \
    fi

# Verify vulnerability is in place
RUN ls -la /usr/bin/guile-3.0 && \
    (ls -la /usr/bin/guile-3.0 | grep -q "[sS]" && echo "SUID bit confirmed on guile-3.0" || \
     echo "WARNING: SUID not set on guile-3.0")
RUN ls -la /usr/bin/guile && \
    (ls -la /usr/bin/guile | grep -q "[sS]" && echo "SUID bit confirmed on guile" || \
     echo "WARNING: SUID not set on guile")

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:aim8Du7h" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]