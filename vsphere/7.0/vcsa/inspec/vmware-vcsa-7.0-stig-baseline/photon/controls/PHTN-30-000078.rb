# encoding: UTF-8

control 'PHTN-30-000078' do
  title "The Photon operating system must configure sshd to disallow Generic
Security Service Application Program Interface (GSSAPI) authentication."
  desc  "GSSAPI authentication is used to provide additional authentication
mechanisms to applications. Allowing GSSAPI authentication through SSH exposes
the systems GSSAPI to remote hosts, increasing the attack surface of the
system."
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # sshd -T|&grep -i GSSAPIAuthentication

    Expected result:

    GSSAPIAuthentication no

    If the output does not match the expected result, this is a finding.
  "
  desc  'fix', "
    Open /etc/ssh/sshd_config with a text editor and ensure that the
\"GSSAPIAuthentication\" line is uncommented and set to the following:

    GSSAPIAuthentication no

    At the command line, execute the following command:

    # systemctl restart sshd.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag stig_id: 'PHTN-30-000078'
  tag cci: 'CCI-000366'
  tag nist: ['CM-6 b']

  describe command('sshd -T|&grep -i GSSAPIAuthentication') do
    its ('stdout.strip') { should cmp 'GSSAPIAuthentication no' }
  end

end

