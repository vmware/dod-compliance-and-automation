control 'PHTN-50-000188' do
  title 'The Photon operating system must configure Secure Shell (SSH) to disallow HostbasedAuthentication.'
  desc  'SSH trust relationships enable trivial lateral spread after a host compromise and therefore must be explicitly disabled.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify the running configuration of sshd:

    # sshd -T|&grep -i HostbasedAuthentication

    Example result:

    hostbasedauthentication no

    If \"HostbasedAuthentication\" is not set to \"no\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/ssh/sshd_config

    Ensure the \"HostbasedAuthentication\" line is uncommented and set to the following:

    HostbasedAuthentication no

    At the command line, run the following command:

    # systemctl restart sshd.service
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000480-GPOS-00229'
  tag gid: 'V-PHTN-50-000188'
  tag rid: 'SV-PHTN-50-000188'
  tag stig_id: 'PHTN-50-000188'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  sshdcommand = input('sshdcommand')
  describe command("#{sshdcommand}|&grep -i HostbasedAuthentication") do
    its('stdout.strip') { should cmp 'HostbasedAuthentication no' }
  end
end
