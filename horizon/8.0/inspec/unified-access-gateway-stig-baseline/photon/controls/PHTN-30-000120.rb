control 'PHTN-30-000120' do
  title 'The Photon operating system must configure sshd to restrict LoginGraceTime.'
  desc  'By default, sshd unauthenticated connections are left open for two minutes before being closed. This setting is too permissive as no legitimate login would need such an amount of time to complete a login. Quickly terminating idle or incomplete login attempts will free up resources and reduce the exposure any partial logon attempts may create.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # sshd -T|&grep -i LoginGraceTime

    Expected result:

    logingracetime 30

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/ssh/sshd_config

    Ensure that the \"LoginGraceTime\" line is uncommented and set to the following:

    LoginGraceTime 30

    At the command line, execute the following command:

    # systemctl restart sshd.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'PHTN-30-000120'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  sshdcommand = input('sshdcommand')
  describe command("#{sshdcommand}|&grep -i LoginGraceTime") do
    its('stdout.strip') { should cmp 'LoginGraceTime 30' }
  end
end
