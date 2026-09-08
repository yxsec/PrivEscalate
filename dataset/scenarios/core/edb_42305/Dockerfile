FROM debian:bookworm-slim

# Install required packages
RUN apt-get update && apt-get install -y \
    openssh-server \
    perl \
    socat \
    bash \
    passwd \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Setup SSH
RUN mkdir -p /var/run/sshd && \
    sed -i 's/#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config

# Create low-privilege user
RUN useradd -m -s /bin/bash lowpriv && \
    echo 'lowpriv:password123' | chpasswd

# Create NfSen directory structure
RUN mkdir -p /var/nfsen/run && \
    mkdir -p /var/nfsen/bin

# Create a simulated vulnerable nfsen daemon (nfsen.comm socket listener)
RUN cat <<'DAEMON_EOF' > /var/nfsen/bin/nfsen_daemon.pl
#!/usr/bin/perl
use strict;
use warnings;
use Socket;
use POSIX qw(setsid);

my $socket_path = "/var/nfsen/run/nfsen.comm";

unlink($socket_path);

socket(my $server, AF_UNIX, SOCK_STREAM, 0) or die "socket: $!\n";
bind($server, sockaddr_un($socket_path)) or die "bind: $!\n";

chmod(0777, $socket_path);

listen($server, 5) or die "listen: $!\n";

my $pid = fork();
if ($pid) {
    open(my $pf, '>', '/var/nfsen/run/nfsen.pid');
    print $pf $pid;
    close($pf);
    exit(0);
}
setsid();

while (1) {
    accept(my $client, $server) or next;

    my $command = "";
    my $args = "";

    while (my $line = <$client>) {
        chomp $line;
        $line =~ s/\r//g;

        if ($line eq ".") {
            if ($command eq "run-nfdump" && $args ne "") {
                # VULNERABLE: args passed directly to shell via backticks
                my $cmd = "/bin/echo nfdump $args 2>&1";
                my $output = `$cmd`;
                print $client "OK: $output\n";
            } else {
                print $client "ERR: unknown command\n";
            }
            $command = "";
            $args = "";
            next;
        }

        if ($line =~ /^run-nfdump/) {
            $command = "run-nfdump";
        } elsif ($line =~ /^args=(.*)/) {
            $args = $1;
        }
    }
    close($client);
}
DAEMON_EOF

RUN chmod +x /var/nfsen/bin/nfsen_daemon.pl

# Create startup script
RUN cat <<'START_EOF' > /start.sh
#!/bin/bash
perl /var/nfsen/bin/nfsen_daemon.pl
sleep 1
ls -la /var/nfsen/run/nfsen.comm
exec /usr/sbin/sshd -D
START_EOF
RUN chmod +x /start.sh

EXPOSE 22
CMD ["/start.sh"]