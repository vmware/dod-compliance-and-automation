control 'UBTU-24-900050' do
  title 'Ubuntu 24.04 LTS must permit only authorized accounts to own the audit configuration files.'
  desc "Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent the auditing of critical events.

Misconfigured audits may degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one."
  desc 'check', 'Verify /etc/audit/audit.rules, /etc/audit/rules.d/*, and /etc/audit/auditd.conf files are owned by "root" account with the following command:

$ sudo ls -al /etc/audit/ /etc/audit/rules.d/
/etc/audit/:

-rw-r-----   1 root root   804 Nov 25 11:01 auditd.conf
 -rw-r-----   1 root root  9128 Dec 27 09:56 audit.rules
-rw-r-----   1 root root   127 Feb  7  2018 audit-stop.rules

drwxr-x---   2 root root  4096 Dec 27 09:56 rules.d

/etc/audit/rules.d/:

 -rw-r----- 1 root root 244 Dec 27 09:56 audit.rules
-rw-r----- 1 root root 10357 Dec 27 09:56 stig.rules

If the /etc/audit/audit.rules, /etc/audit/rules.d/*, or /etc/audit/auditd.conf file is owned by a user other than "root", this is a finding.'
  desc 'fix', 'Configure /etc/audit/audit.rules, /etc/audit/rules.d/*, and /etc/audit/auditd.conf files to be owned by "root" user by using the following command:

$ sudo chown root /etc/audit/audit*.{rules,conf} /etc/audit/rules.d/*'
  impact 0.5
  tag check_id: 'C-74809r1066815_chk'
  tag severity: 'medium'
  tag gid: 'V-270776'
  tag rid: 'SV-270776r1066817_rule'
  tag stig_id: 'UBTU-24-900050'
  tag gtitle: 'SRG-OS-000063-GPOS-00032'
  tag fix_id: 'F-74710r1066816_fix'
  tag 'documentable'
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']

  audit_conf_files = command('find /etc/audit -type f \( -iname "*.rules" -o -iname "*.conf" \)').stdout.strip.split("\n")

  audit_conf_files.each do |conf|
    describe file(conf) do
      it { should exist }
      its('owner') { should cmp 'root' }
    end
  end
end
