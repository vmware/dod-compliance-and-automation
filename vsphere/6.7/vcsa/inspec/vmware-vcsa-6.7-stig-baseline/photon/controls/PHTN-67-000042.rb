control 'PHTN-67-000042' do
  title 'The Photon operating system messages file must be owned by root.'
  desc  "Only authorized personnel should be aware of errors and the details of
the errors. Error messages are an indicator of an organization's operational
state and can provide sensitive information to an unprivileged attacker."
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # stat -c \"%n is owned by %U and group owned by %G\"
/var/log/vmware/messages

    If /var/log/vmware/messages is not owned by root or not group owned by
root, this is a finding.
  "
  desc 'fix', "
    At the command line, execute the following command:

    # chown root:root /var/log/vmware/messages
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag gid: 'V-239114'
  tag rid: 'SV-239114r675150_rule'
  tag stig_id: 'PHTN-67-000042'
  tag fix_id: 'F-42284r675149_fix'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']

  describe file('/var/log/vmware/messages') do
    its('owner') { should cmp 'root' }
    its('group') { should cmp 'root' }
  end
end
