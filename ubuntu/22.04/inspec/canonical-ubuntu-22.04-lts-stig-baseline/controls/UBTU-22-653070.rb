control 'UBTU-22-653070' do
  title 'Ubuntu 22.04 LTS must permit only authorized accounts to own the audit configuration files.'
  desc "Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent the auditing of critical events.

Misconfigured audits may degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one."
  desc 'check', %q(Verify that "/etc/audit/audit.rules", "/etc/audit/auditd.conf", and "/etc/audit/rules.d/*" files are owned by root account by using the following command:

     $ sudo ls -al /etc/audit/audit.rules /etc/audit/auditd.conf /etc/audit/rules.d/* | awk '{print $3, $9}'
     root /etc/audit/audit.rules
     root /etc/audit/auditd.conf
     root /etc/audit/rules.d/audit.rules

If "/etc/audit/audit.rules", "/etc/audit/auditd.conf", or "/etc/audit/rules.d/*" files are owned by a user other than "root", this is a finding.)
  desc 'fix', 'Configure "/etc/audit/audit.rules", "/etc/audit/rules.d/*", and "/etc/audit/auditd.conf" files to be owned by root by using the following command:

     $ sudo chown -R root /etc/audit/audit.rules /etc/audit/auditd.conf /etc/audit/rules.d/*'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64331r953617_chk'
  tag severity: 'medium'
  tag gid: 'V-260602'
  tag rid: 'SV-260602r958444_rule'
  tag stig_id: 'UBTU-22-653070'
  tag gtitle: 'SRG-OS-000063-GPOS-00032'
  tag fix_id: 'F-64239r953618_fix'
  tag 'documentable'
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']

  files1 = command('find /etc/audit/ -type f \( -iname \*.rules -o -iname \*.conf \)').stdout.strip.split("\n").entries
  files2 = command('find /etc/audit/rules.d/* -type f').stdout.strip.split("\n").entries

  audit_conf_files = files1 + files2

  audit_conf_files.each do |conf|
    describe file(conf) do
      its('owner') { should cmp 'root' }
    end
  end
end
