control 'PHTN-50-000221' do
  title 'The Photon operating system must configure Secure Shell (SSH) to restrict LoginGraceTime.'
  desc  'By default, SSH unauthenticated connections are left open for two minutes before being closed. This setting is too permissive as no legitimate login would need such an amount of time to complete a login. Quickly terminating idle or incomplete login attempts will free up resources and reduce the exposure any partial logon attempts may create.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify the running configuration of sshd:

    # sshd -T|&grep -i LoginGraceTime

    Example result:

    logingracetime 30

    If \"LoginGraceTime\" is not set to \"30\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/ssh/sshd_config

    Ensure the \"LoginGraceTime\" line is uncommented and set to the following:

    LoginGraceTime 30

    At the command line, run the following command:

    # systemctl restart sshd.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-PHTN-50-000221'
  tag rid: 'SV-PHTN-50-000221'
  tag stig_id: 'PHTN-50-000221'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  sshdcommand = input('sshdcommand')
  describe command("#{sshdcommand}|&grep -i LoginGraceTime") do
    its('stdout.strip') { should cmp 'LoginGraceTime 30' }
  end
end
