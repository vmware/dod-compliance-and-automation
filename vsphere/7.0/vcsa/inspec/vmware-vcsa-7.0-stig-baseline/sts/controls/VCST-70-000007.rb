# encoding: UTF-8

control 'VCST-70-000007' do
  title "Security Token Service log files must only be modifiable by privileged
users."
  desc  "Log data is essential in the investigation of events. The accuracy of
the information is always pertinent. One of the first steps an attacker will
undertake is the modification or deletion of log records to cover his tracks
and prolong discovery. The web server must protect the log data from
unauthorized modification. Security Token Service restricts all modification of
log files by default but this configuration must be verified."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # find /storage/log/vmware/sso/ -xdev -type f -a '(' -perm -o+w -o -not
-user root -o -not -group root ')' -exec ls -ld {} \\;

    If any files are returned, this is a finding.
  "
  desc  'fix', "
    At the command prompt, execute the following commands:

    # chmod o-w <file>
    # chown root:root <file>

    Note: Subsitute <file> with the listed file.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000119-WSR-000069'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCST-70-000007'
  tag fix_id: nil
  tag cci: 'CCI-000163'
  tag nist: ['AU-9']

  command("find '#{input('logPath')}' -type f -xdev").stdout.split.each do | fname |
    describe file(fname) do
      it { should_not be_more_permissive_than('0644') }
      its('owner') {should eq 'root'}
      its('group') {should eq 'root'}
    end
  end

end

