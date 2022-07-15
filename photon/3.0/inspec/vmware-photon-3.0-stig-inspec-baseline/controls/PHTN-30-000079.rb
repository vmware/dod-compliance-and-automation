control 'PHTN-30-000079' do
  title 'The Photon operating system must configure sshd to disable environment processing.'
  desc  'Enabling environment processing may enable users to bypass access restrictions in some configurations and must therefore be disabled.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    sshd -T|&grep -i PermitUserEnvironment

    Expected result:

    PermitUserEnvironment no

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/ssh/sshd_config

    Ensure that the \"PermitUserEnvironment\" line is uncommented and set to the following:

    PermitUserEnvironment no

    At the command line, execute the following command:

    # systemctl restart sshd.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'PHTN-30-000079'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  sshdcommand = input('sshdcommand')
  describe command("#{sshdcommand}|&grep -i PermitUserEnvironment") do
    its('stdout.strip') { should cmp 'PermitUserEnvironment no' }
  end
end
