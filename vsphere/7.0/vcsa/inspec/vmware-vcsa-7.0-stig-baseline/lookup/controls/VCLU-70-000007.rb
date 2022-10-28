control 'VCLU-70-000007' do
  title 'Lookup Service log files must only be accessible by privileged users.'
  desc  "
    Log data is essential in the investigation of events. If log data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity would be difficult, if not impossible, to achieve.

    In addition, access to log records provides information an attacker could potentially use to their advantage since each event record might contain communication ports, protocols, services, trust relationships, user names, etc. The Lookup Service restricts all access to log file by default but this configuration must be verified.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # find /var/log/vmware/lookupsvc -xdev -type f -a '(' -perm /137 -o -not -user root -o -not -group root ')' -exec ls -ld {} \\;

    If any files are returned, this is a finding.
  "
  desc 'fix', "
    At the command prompt, execute the following command(s):

    # chmod 640 /var/log/vmware/lookupsvc/<file>
    # chown root:root /var/log/vmware/lookupsvc/<file>

    Note: Subsitute <file> with the listed file.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000118-WSR-000068'
  tag satisfies: ['SRG-APP-000119-WSR-000069', 'SRG-APP-000120-WSR-000070']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCLU-70-000007'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9']

  command("find '#{input('logPath')}' -type f -xdev").stdout.split.each do |fname|
    describe file(fname) do
      it { should_not be_more_permissive_than('0640') }
      its('owner') { should eq 'root' }
      its('group') { should eq 'root' }
    end
  end
end
