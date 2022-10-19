control 'PHTN-30-000078' do
  title 'The Photon operating system must configure sshd to disallow Generic Security Service Application Program Interface (GSSAPI) authentication.'
  desc  "GSSAPI authentication is used to provide additional authentication mechanisms to applications. Allowing GSSAPI authentication through SSH exposes the system's GSSAPI to remote hosts, increasing the attack surface of the system."
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # sshd -T|&grep -i GSSAPIAuthentication

    Expected result:

    GSSAPIAuthentication no

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/ssh/sshd_config

    Ensure that the \"GSSAPIAuthentication\" line is uncommented and set to the following:

    GSSAPIAuthentication no

    At the command line, execute the following command:

    # systemctl restart sshd.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'PHTN-30-000078'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  sshdcommand = input('sshdcommand')
  describe command("#{sshdcommand}|&grep -i GSSAPIAuthentication") do
    its('stdout.strip') { should cmp 'GSSAPIAuthentication no' }
  end
end
