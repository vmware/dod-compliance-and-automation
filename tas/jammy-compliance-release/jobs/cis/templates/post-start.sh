#!/bin/bash -e

mv /etc/audit/audit.rules "/etc/audit/audit.rules.backup.$(date +%s)"
augenrules --load

service sshd restart
service auditd restart
