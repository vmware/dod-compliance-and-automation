control 'PHTN-67-000041' do
  title 'The Photon operating system /var/log directory must be owned by root.'
  desc  "Only authorized personnel should be aware of errors and the details of
the errors. Error messages are an indicator of an organization's operational
state and can provide sensitive information to an unprivileged attacker."
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # stat -c \"%n is owned by %U and group owned by %G\" /var/log

    If the /var/log is not owned by root, this is a finding.
  "
  desc 'fix', "
    At the command line, execute the following command:

    # chown root:root /var/log
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag gid: 'V-239113'
  tag rid: 'SV-239113r675147_rule'
  tag stig_id: 'PHTN-67-000041'
  tag fix_id: 'F-42283r675146_fix'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']

  describe directory('/var/log') do
    its('owner') { should cmp 'root' }
  end
end
