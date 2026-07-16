control 'PHTN-50-000216' do
  title 'The Photon operating system must configure Secure Shell (SSH) to display the last login immediately after authentication.'
  desc  'Providing users with feedback on the last time they logged on via SSH facilitates user recognition and reporting of unauthorized account use.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify the running configuration of sshd:

    # sshd -T|&grep -i PrintLastLog

    Example result:

    printlastlog yes

    If \"PrintLastLog\" is not set to \"yes\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/ssh/sshd_config

    Ensure the \"PrintLastLog\" line is uncommented and set to the following:

    PrintLastLog yes

    At the command line, run the following command:

    # systemctl restart sshd.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-PHTN-50-000216'
  tag rid: 'SV-PHTN-50-000216'
  tag stig_id: 'PHTN-50-000216'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  sshdcommand = input('sshdcommand')
  describe command("#{sshdcommand}|&grep -i PrintLastLog") do
    its('stdout.strip') { should cmp 'PrintLastLog yes' }
  end
end
