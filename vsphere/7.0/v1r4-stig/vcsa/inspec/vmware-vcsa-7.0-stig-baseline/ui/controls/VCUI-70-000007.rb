control 'VCUI-70-000007' do
  title 'vSphere UI log files must only be accessible by privileged users.'
  desc 'Log data is essential in the investigation of events. If log data were to become compromised, competent forensic analysis and discovery of the true source of potentially malicious system activity would be difficult, if not impossible, to achieve.

In addition, access to log records provides information an attacker could use to their advantage since each event record might contain communication ports, protocols, services, trust relationships, usernames, etc. The vSphere UI restricts all access to log files by default, but this configuration must be verified.

'
  desc 'check', "At the command prompt, run the following command:

# find /var/log/vmware/vsphere-ui/ -xdev -type f -a '(' -perm -o+w -o -not -user vsphere-ui -o -not -group users -a -not -group root ')' -exec ls -ld {} \\;

If any files are returned, this is a finding."
  desc 'fix', 'At the command prompt, run the following commands:

# chmod 644 /storage/log/vmware/vsphere-ui/logs/<file>
# chown vsphere-ui:users /storage/log/vmware/vsphere-ui/logs/<file>

Note: Substitute <file> with the listed file.'
  impact 0.5
  tag check_id: 'C-60459r889349_chk'
  tag severity: 'medium'
  tag gid: 'V-256784'
  tag rid: 'SV-256784r889351_rule'
  tag stig_id: 'VCUI-70-000007'
  tag gtitle: 'SRG-APP-000118-WSR-000068'
  tag fix_id: 'F-60402r889350_fix'
  tag satisfies: ['SRG-APP-000118-WSR-000068', 'SRG-APP-000119-WSR-000069', 'SRG-APP-000120-WSR-000070']
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a']

  command("find '#{input('logPath')}' -type f -xdev").stdout.split.each do |fname|
    describe file(fname) do
      it { should_not be_writable.by('others') }
      its('owner') { should cmp 'vsphere-ui' }
      its('group') { should cmp('root').or cmp('users') }
    end
  end
end
