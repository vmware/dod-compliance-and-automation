control 'PHTN-30-000041' do
  title 'The Photon operating system messages file have the correct ownership and file permissions.'
  desc  "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state and can provide sensitive information to an unprivileged attacker."
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # stat -c \"%n is owned by %U and group owned by %G with %a permissions\" /var/log/messages

    If the /var/log/messages directory is not owned by root or not group owned by root or the file permissions are more permission than 640, this is a finding.
  "
  desc 'fix', "
    At the command line, execute the following command(s):

    # chown root:root /var/log/messages

    # chmod 0640 /var/log/messages
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag gid: 'V-PHTN-30-000041'
  tag rid: 'SV-PHTN-30-000041'
  tag stig_id: 'PHTN-30-000041'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']

  messages = file('/var/log/messages')

  if messages.exist?
    describe messages do
      its('owner') { should cmp 'root' }
      its('group') { should cmp 'root' }
      it { should_not be_more_permissive_than('0640') }
    end
  else
    describe 'No /var/log/messages file found...skipping...' do
      skip 'No /var/log/messages file found...skipping...'
    end
  end
end
