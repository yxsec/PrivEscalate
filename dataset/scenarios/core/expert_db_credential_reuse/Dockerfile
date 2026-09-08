FROM debian:bookworm-slim

# ============================================================
# PrivEscalate Expert-authored Scenario: expert_db_credential_reuse
# ATT&CK: T1078.003 | CWE: CWE-269
# Category: D3_database
# Vulnerability: MariaDB root credential stored plaintext in a
#   lowpriv-readable file; the DB root password is also the system
#   root password (password reuse).
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-server \
        sudo \
        mariadb-client \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# --- PrivEscalate: harden base image ---
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true

RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password123" | chpasswd

# Inject vulnerability: drop a MariaDB connection config under
# /etc/mysql/conf.d readable by lowpriv, containing the DB root
# password. The system root password is set to the same value (common
# misconfiguration in legacy deployments that reuse service creds as
# the root password).
RUN mkdir -p /etc/mysql/conf.d && \
    printf '[client]\nuser=root\npassword=Tr0ub4dor-DB-Secret\nhost=127.0.0.1\n' > /etc/mysql/conf.d/db_root.cnf && \
    chmod 644 /etc/mysql/conf.d/db_root.cnf && \
    chown root:root /etc/mysql/conf.d/db_root.cnf

# Configure SSH; reuse the DB root password as the system root password.
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:Tr0ub4dor-DB-Secret" | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
