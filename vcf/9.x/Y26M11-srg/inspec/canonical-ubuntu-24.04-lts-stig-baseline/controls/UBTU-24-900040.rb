control 'UBTU-24-900040' do
  title 'Ubuntu 24.04 LTS must be configured so that audit configuration files are not write-accessible by unauthorized users.'
  desc "Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent the auditing of critical events.

Misconfigured audits may degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one."
  desc 'check', 'Verify /etc/audit/audit.rules, /etc/audit/rules.d/*, and /etc/audit/auditd.conf files have a mode of "0640" or less permissive with the following command:

$ sudo ls -al /etc/audit/ /etc/audit/rules.d/
/etc/audit/:

-rw-r-----   1 root root   804 Nov 25 11:01 auditd.conf
 -rw-r-----   1 root root  9128 Dec 27 09:56 audit.rules
-rw-r-----   1 root root   127 Feb  7  2018 audit-stop.rules

drwxr-x---   2 root root  4096 Dec 27 09:56 rules.d

/etc/audit/rules.d/:

 -rw-r----- 1 root root 244 Dec 27 09:56 audit.rules
-rw-r----- 1 root root 10357 Dec 27 09:56 stig.rules

If /etc/audit/audit.rule, /etc/audit/rules.d/*, or /etc/audit/auditd.conf files have a mode more permissive than "0640", this is a finding.'
  desc 'fix', 'Configure /etc/audit/audit.rules, /etc/audit/rules.d/*, and /etc/audit/auditd.conf files to have a mode of "0640" by using the following command:

$ sudo chmod -R 0640 /etc/audit/audit*.{rules,conf} /etc/audit/rules.d/*'
  impact 0.5
  tag check_id: 'C-74808r1068368_chk'
  tag severity: 'medium'
  tag gid: 'V-270775'
  tag rid: 'SV-270775r1068369_rule'
  tag stig_id: 'UBTU-24-900040'
  tag gtitle: 'SRG-OS-000063-GPOS-00032'
  tag fix_id: 'F-74709r1066813_fix'
  tag 'documentable'
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']

  audit_conf_files = command('find /etc/audit -type f \( -iname "*.rules" -o -iname "*.conf" \)').stdout.strip.split("\n")

  audit_conf_files.each do |conf|
    describe file(conf) do
      it { should exist }
      its('mode') { should cmp <= 0o640 }
    end
  end
end
