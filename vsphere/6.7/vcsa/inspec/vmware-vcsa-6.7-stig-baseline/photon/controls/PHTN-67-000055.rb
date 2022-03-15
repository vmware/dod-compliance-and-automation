control 'PHTN-67-000055' do
  title "The Photon operating system must configure sshd with a specific
ListenAddress."
  desc  "Without specifying a ListenAddress, sshd will listen on all
interfaces. In situations with multiple interfaces, this may not be intended
behavior and could lead to offering remote access on an unapproved network."
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # sshd -T|&grep -i ListenAddress

    If the ListenAddress is not configured to the VCSA management IP, this is a
finding.
  "
  desc 'fix', "
    Open /etc/ssh/sshd_config with a text editor.

    Ensure that the \"ListenAddress\" line is uncommented and set to a valid
local IP:

    Example:

    ListenAddress 169.254.1.2

    Replace \"169.254.1.2\" with the management address of the VCSA.

    At the command line, execute the following command:

    # service sshd reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000297-GPOS-00115'
  tag gid: 'V-239126'
  tag rid: 'SV-239126r675186_rule'
  tag stig_id: 'PHTN-67-000055'
  tag fix_id: 'F-42296r675185_fix'
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']

  photonIp = command("ip -br addr show eth0 |&awk '{print $3}' |&cut -d'/' -f1").stdout.strip
  describe command('sshd -T|&grep -i ListenAddress') do
    its('stdout.strip') { should match /listenaddress #{photonIp}/ }
  end
end
