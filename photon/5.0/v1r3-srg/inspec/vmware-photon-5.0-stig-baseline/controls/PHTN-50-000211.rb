control 'PHTN-50-000211' do
  title 'The Photon operating system must configure Secure Shell (SSH) to disallow Generic Security Service Application Program Interface (GSSAPI) authentication.'
  desc  "GSSAPI authentication is used to provide additional authentication mechanisms to applications. Allowing GSSAPI authentication through Secure Shell (SSH) exposes the system's GSSAPI to remote hosts, increasing the attack surface of the system."
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify the running configuration of sshd:

    # sshd -T|&grep -i GSSAPIAuthentication

    Example result:

    gssapiauthentication no

    If \"GSSAPIAuthentication\" is not set to \"no\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/ssh/sshd_config

    Ensure the \"GSSAPIAuthentication\" line is uncommented and set to the following:

    GSSAPIAuthentication no

    At the command line, run the following command:

    # systemctl restart sshd.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-PHTN-50-000211'
  tag rid: 'SV-PHTN-50-000211'
  tag stig_id: 'PHTN-50-000211'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  sshdcommand = input('sshdcommand')
  describe command("#{sshdcommand}|&grep -i GSSAPIAuthentication") do
    its('stdout.strip') { should cmp 'GSSAPIAuthentication no' }
  end
end
