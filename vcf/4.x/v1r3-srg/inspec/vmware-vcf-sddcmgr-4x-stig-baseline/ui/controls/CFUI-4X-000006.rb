control 'CFUI-4X-000006' do
  title 'The SDDC Manager UI service systemd service definition permissions must be configured appropriately.'
  desc  "If the systemd service definition file is not adequately protected then non-privileged users could alter it and change the behavior of the service to behave maliciously or affect it's functionality."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # find /etc/systemd/system/sddc-manager-ui* -xdev -type f -a '(' -perm /133 -o -not -user root -o -not -group root ')' -exec ls -ld {} \\;

    If the command produces any output, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following command(s):

    # chmod 644 <file>
    # chmod root:root <file>

    Repeat the command for each file that was returned.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000435-WSR-000147'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'CFUI-4X-000006'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5']

  command('find /etc/systemd/system/sddc-manager-ui* -xdev -type f').stdout.split.each do |fname|
    describe file(fname) do
      its('group') { should cmp 'root' }
      its('owner') { should cmp 'root' }
      it { should_not be_more_permissive_than('0644') }
    end
  end
end
