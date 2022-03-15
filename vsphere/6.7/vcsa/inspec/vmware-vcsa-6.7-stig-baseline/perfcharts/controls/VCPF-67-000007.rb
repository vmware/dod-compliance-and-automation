control 'VCPF-67-000007' do
  title "Performance Charts log files must only be modifiable by privileged
users."
  desc  "Log data is essential in the investigation of events. The accuracy of
the information is always pertinent. One of the first steps an attacker will
undertake is the modification or deletion of log records to cover tracks and
prolong discovery. The web server must protect the log data from unauthorized
modification. Performance Charts restricts all modification of log files by
default, but this configuration must be verified.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # find /storage/log/vmware/perfcharts/ -xdev -type f -a '(' -perm -o+w -o
-not -user root -o -not -group root ')' -exec ls -ld {} \\;

    If any files are returned, this is a finding.
  "
  desc 'fix', "
    At the command prompt, execute the following commands:

    # chmod o-w <file>

    # chown root:root <file>

    Note: Substitute <file> with the listed file.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000119-WSR-000069'
  tag satisfies: %w(SRG-APP-000119-WSR-000069 SRG-APP-000120-WSR-000070)
  tag gid: 'V-239408'
  tag rid: 'SV-239408r674947_rule'
  tag stig_id: 'VCPF-67-000007'
  tag fix_id: 'F-42600r674946_fix'
  tag cci: %w(CCI-000163 CCI-000164)
  tag nist: %w(AU-9 AU-9)

  command("find '#{input('logPath')}' -type f -xdev").stdout.split.each do |fname|
    describe file(fname) do
      it { should_not be_more_permissive_than('0644') }
      its('owner') { should eq 'root' }
      its('group') { should eq 'root' }
    end
  end
end
