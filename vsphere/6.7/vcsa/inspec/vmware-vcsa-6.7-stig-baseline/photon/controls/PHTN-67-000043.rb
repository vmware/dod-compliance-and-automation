control 'PHTN-67-000043' do
  title "The Photon operating system messages file must have mode 0640 or less
permissive."
  desc  "Only authorized personnel should be aware of errors and the details of
the errors. Error messages are an indicator of an organization's operational
state and can provide sensitive information to an unprivileged attacker."
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # stat -c \"%n permissions are %a\" /var/log/vmware/messages

    If the permissions on the file are more permissive than 0640, this is a
finding.
  "
  desc 'fix', "
    At the command line, execute the following command:

    # chmod 0640 /var/log/vmware/messages
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag gid: 'V-239115'
  tag rid: 'SV-239115r675153_rule'
  tag stig_id: 'PHTN-67-000043'
  tag fix_id: 'F-42285r675152_fix'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']

  describe file('/var/log/vmware/messages') do
    it { should_not be_more_permissive_than('0640') }
  end
end
