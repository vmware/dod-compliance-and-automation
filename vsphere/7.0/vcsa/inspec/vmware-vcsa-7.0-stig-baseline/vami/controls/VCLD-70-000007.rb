control 'VCLD-70-000007' do
  title 'VAMI log files must only be accessible by privileged users.'
  desc 'Log data is essential in the investigation of events. If log data were to become compromised, competent forensic analysis and discovery of the true source of potentially malicious system activity would be difficult, if not impossible, to achieve.

In addition, access to log records provides information an attacker could use to their advantage because each event record might contain communication ports, protocols, services, trust relationships, user names, etc.

'
  desc 'check', "At the command prompt, run the following command:

# find /opt/vmware/var/log/lighttpd/ -xdev -type f -a '(' -perm -o+w -o -not -user root -o -not -group root ')' -exec ls -ld {} \\;

If any files are returned, this is a finding."
  desc 'fix', 'At the command prompt, run the following commands:

# chmod o-w <file>
# chown root:root <file>

Note: Substitute <file> with the listed file.'
  impact 0.5
  tag check_id: 'C-60326r918982_chk'
  tag severity: 'medium'
  tag gid: 'V-256651'
  tag rid: 'SV-256651r918984_rule'
  tag stig_id: 'VCLD-70-000007'
  tag gtitle: 'SRG-APP-000118-WSR-000068'
  tag fix_id: 'F-60269r918983_fix'
  tag satisfies: ['SRG-APP-000118-WSR-000068', 'SRG-APP-000119-WSR-000069', 'SRG-APP-000120-WSR-000070']
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a']

  command("find '#{input('logPath')}' -type f -xdev").stdout.split.each do |fname|
    describe file(fname) do
      it { should_not be_writable.by('others') }
      its('owner') { should cmp 'root' }
      its('group') { should cmp 'root' }
    end
  end
end
