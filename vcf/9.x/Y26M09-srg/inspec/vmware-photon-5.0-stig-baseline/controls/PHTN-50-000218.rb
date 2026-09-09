control 'PHTN-50-000218' do
  title 'The Photon operating system must configure Secure Shell (SSH) to ignore user-specific known_host files.'
  desc  'SSH trust relationships enable trivial lateral spread after a host compromise and therefore must be explicitly disabled. Individual users can have a local list of trusted remote machines which must also be ignored while disabling host-based authentication generally.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify the running configuration of sshd:

    # sshd -T|&grep -i IgnoreUserKnownHosts

    Expected result:

    ignoreuserknownhosts yes

    If \"IgnoreUserKnownHosts\" is not set to \"yes\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/ssh/sshd_config

    Ensure the \"IgnoreUserKnownHosts\" line is uncommented and set to the following:

    IgnoreUserKnownHosts yes

    At the command line, run the following command:

    # systemctl restart sshd.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-PHTN-50-000218'
  tag rid: 'SV-PHTN-50-000218'
  tag stig_id: 'PHTN-50-000218'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  sshdcommand = input('sshdcommand')
  describe command("#{sshdcommand}|&grep -i IgnoreUserKnownHosts") do
    its('stdout.strip') { should cmp 'IgnoreUserKnownHosts yes' }
  end
end
