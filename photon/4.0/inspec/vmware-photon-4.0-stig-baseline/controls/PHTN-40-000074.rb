control 'PHTN-40-000074' do
  title 'The Photon operating system messages file must only be accessible to authorized users.'
  desc  "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the operating system or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives."
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify permissions on the /var/log/messages file:

    # stat -c \"%n is owned by %U and group owned by %G with permissions of %a\" /var/log/messages

    Expected result:

    /var/log/messages is owned by root and group owned by root with permissions of 640

    If the /var/log directory is not owned by root, this is a finding.
    If the /var/log directory is not group owned by root, this is a finding.
    If the /var/log directory permissions are not set to 0640 or less, this is a finding.
  "
  desc 'fix', "
    At the command line, run the following commands:

    # chown root:root /var/log/messages
    # chmod 0640 /var/log/messages
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag gid: 'V-PHTN-40-000074'
  tag rid: 'SV-PHTN-40-000074'
  tag stig_id: 'PHTN-40-000074'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']

  describe file('/var/log/messages') do
    its('owner') { should cmp 'root' }
    its('group') { should cmp 'root' }
    it { should_not be_more_permissive_than('0640') }
  end
end
