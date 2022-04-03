control 'VCST-67-000007' do
  title "Security Token Service log files must only be modifiable by privileged
users."
  desc  "Log data is essential in the investigation of events. The accuracy of
the information is always pertinent. One of the first steps an attacker will
undertake is the modification or deletion of log records to cover tracks and
prolong discovery. The web server must protect the log data from unauthorized
modification. Security Token Service restricts all modification of log files by
default, but this configuration must be verified.
  "
  desc  'rationale', ''
  desc  'check', "
    Connect to the PSC, whether external or embedded.

    At the command prompt, execute the following command:

    # find /storage/log/vmware/sso/ -xdev -type f -a '(' -perm -o+w -o -not
-user root -o -not -group root ')' -exec ls -ld {} \\;

    If any files are returned, this is a finding.
  "
  desc 'fix', "
    Connect to the PSC, whether external or embedded.

    At the command prompt, execute the following commands:

    # chmod o-w <file>
    # chown root:root <file>

    Note: Substitute <file> with the listed file.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000119-WSR-000069'
  tag satisfies: ['SRG-APP-000119-WSR-000069', 'SRG-APP-000120-WSR-000070']
  tag gid: 'V-239658'
  tag rid: 'SV-239658r816699_rule'
  tag stig_id: 'VCST-67-000007'
  tag fix_id: 'F-42850r816698_fix'
  tag cci: ['CCI-000163', 'CCI-000164']
  tag nist: ['AU-9', 'AU-9']

  command("find '#{input('logPath')}' -type f -xdev").stdout.split.each do |fname|
    describe file(fname) do
      it { should_not be_more_permissive_than('0644') }
      its('owner') { should eq 'root' }
      its('group') { should eq 'root' }
    end
  end
end
