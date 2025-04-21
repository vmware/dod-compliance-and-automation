control 'VCLU-70-000007' do
  title 'Lookup Service log files must only be accessible by privileged users.'
  desc 'Log data is essential in the investigation of events. If log data were to become compromised, competent forensic analysis and discovery of the true source of potentially malicious system activity would be difficult, if not impossible, to achieve.

In addition, access to log records provides information an attacker could use to their advantage because each event record might contain communication ports, protocols, services, trust relationships, usernames, etc. The Lookup Service restricts all access to log files by default, but this configuration must be verified.

'
  desc 'check', "At the command prompt, run the following command:

# find /var/log/vmware/lookupsvc -xdev -type f ! -name lookupsvc-init.log -a '(' -perm -o+w -o -not -user lookupsvc -o -not -group lookupsvc ')' -exec ls -ld {} \\;

If any files are returned, this is a finding.

Note: Prior to Update 3h, the user and group should be root."
  desc 'fix', 'At the command prompt, run the following commands:

# chmod o-w /var/log/vmware/lookupsvc/<file>
# chown lookupsvc:lookupsvc /var/log/vmware/lookupsvc/<file>

Note: Substitute <file> with the listed file.'
  impact 0.5
  tag check_id: 'C-60387r918956_chk'
  tag severity: 'medium'
  tag gid: 'V-256712'
  tag rid: 'SV-256712r918958_rule'
  tag stig_id: 'VCLU-70-000007'
  tag gtitle: 'SRG-APP-000118-WSR-000068'
  tag fix_id: 'F-60330r918957_fix'
  tag satisfies: ['SRG-APP-000118-WSR-000068', 'SRG-APP-000119-WSR-000069', 'SRG-APP-000120-WSR-000070']
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a']

  command("find '#{input('logPath')}' -type f -xdev ! -name lookupsvc-init.log").stdout.split.each do |fname|
    describe file(fname) do
      it { should_not be_writable.by('others') }
      its('owner') { should cmp 'lookupsvc' }
      its('group') { should cmp 'lookupsvc' }
    end
  end
end
