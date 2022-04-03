control 'PHTN-67-000123' do
  title "The Photon operating system must configure sshd to disallow
HostbasedAuthentication."
  desc  "SSH trust relationships enable trivial lateral spread after a host
compromise and therefore must be explicitly disabled."
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # sshd -T|&grep -i HostbasedAuthentication

    Expected result:

    hostbasedauthentication no

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Open /etc/ssh/sshd_config with a text editor.

    Ensure that the \"HostbasedAuthentication\" line is uncommented and set to
the following:

    HostbasedAuthentication no

    At the command line, execute the following command:

    # service sshd reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00229'
  tag gid: 'V-239194'
  tag rid: 'SV-239194r675390_rule'
  tag stig_id: 'PHTN-67-000123'
  tag fix_id: 'F-42364r675389_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe command('sshd -T|&grep -i HostbasedAuthentication') do
    its('stdout.strip') { should cmp 'HostbasedAuthentication no' }
  end
end
