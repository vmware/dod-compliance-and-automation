control 'PHTN-40-000201' do
  title 'The Photon operating system must enable sshd authentication logging.'
  desc  "
    Automated monitoring of remote access sessions allows organizations to detect cyberattacks and ensure ongoing compliance with remote access policies by auditing connection activities.

    The INFO LogLevel is required, at least, to ensure the capturing of failed login events.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify the running configuration of sshd:

    # sshd -T|&grep -i LogLevel

    Expected result:

    LogLevel INFO

    If there is no output or if the output does not match expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/ssh/sshd_config

    Ensure the \"LogLevel\" line is uncommented and set to the following:

    LogLevel INFO

    At the command line, run the following command:

    # systemctl restart sshd.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000032-GPOS-00013'
  tag gid: 'V-PHTN-40-000201'
  tag rid: 'SV-PHTN-40-000201'
  tag stig_id: 'PHTN-40-000201'
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']

  sshdcommand = input('sshdcommand')
  describe command("#{sshdcommand}|&grep -i LogLevel") do
    its('stdout.strip') { should cmp 'LogLevel INFO' }
  end
end
