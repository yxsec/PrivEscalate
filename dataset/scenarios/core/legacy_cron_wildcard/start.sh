#!/bin/bash
# Start both cron and sshd for scenarios that need cron
service cron start
exec /usr/sbin/sshd -D
