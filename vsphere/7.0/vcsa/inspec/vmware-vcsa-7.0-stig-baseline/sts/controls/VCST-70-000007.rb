# encoding: UTF-8

control 'VCST-70-000007' do
  title "Security Token Service log files must only be modifiable by privileged
users."
  desc  "Verifying that the Security Token Service application code is
unchanged from it's shipping state is essential for file validation and
non-repudiation of the Security Token Service. There is no reason that the MD5
hash of the rpm original files should be changed after installation, excluding
configuration files."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # find /storage/log/vmware/sso/ -xdev -type f -a '(' -perm -o+w -o -not
-user root -o -not -group root ')' -exec ls -ld {} \\;

    If any files are returned, this is a finding.
  "
  desc  'fix', "
    At the command prompt, execute the following command(s):

    # chmod o-w <file>
    # chown root:root <file>

    Note: Substitute <file> with the listed file.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000119-WSR-000069'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCST-70-000007'
  tag fix_id: nil
  tag cci: ['CCI-000163']
  tag nist: ['AU-9']

  command("find '#{input('logPath')}' -type f -xdev").stdout.split.each do | fname |
    describe file(fname) do
      it { should_not be_more_permissive_than('0644') }
      its('owner') {should eq 'root'}
      its('group') {should eq 'root'}
    end
  end

end

