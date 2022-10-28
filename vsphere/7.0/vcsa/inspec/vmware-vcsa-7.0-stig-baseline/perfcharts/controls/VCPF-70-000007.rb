control 'VCPF-70-000007' do
  title 'Performance Charts log files must only be modifiable by privileged users.'
  desc  'Log data is essential in the investigation of events. The accuracy of the information is always pertinent. One of the first steps an attacker will undertake is the modification or deletion of log records to cover tracks and prolong discovery. The web server must protect the log data from unauthorized modification. Performance Charts restricts all modification of log files by default, but this configuration must be verified.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # find /storage/log/vmware/perfcharts/ -xdev -type f -a '(' -perm -o+w -o -not -user perfcharts -o -not -group users ')' -exec ls -ld {} \\;

    If any files are returned, this is a finding.
  "
  desc 'fix', "
    At the command prompt, execute the following command(s):

    # chmod o-w <file>
    # chown perfcharts:users <file>

    Note: Subsitute <file> with the listed file.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000119-WSR-000069'
  tag satisfies: ['SRG-APP-000118-WSR-000068', 'SRG-APP-000120-WSR-000070']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCPF-70-000007'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9']

  command("find '#{input('logPath')}' -type f -xdev").stdout.split.each do |fname|
    describe file(fname) do
      it { should_not be_more_permissive_than('0644') }
      its('owner') { should eq 'perfcharts' }
      its('group') { should eq 'users' }
    end
  end
end
