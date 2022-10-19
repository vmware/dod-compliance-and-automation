control 'PHTN-30-000008' do
  title 'The Photon operating system must have the sshd LogLevel set to "INFO".'
  desc  "
    Automated monitoring of remote access sessions allows organizations to detect cyberattacks and ensure ongoing compliance with remote access policies by auditing connection activities.

    The INFO LogLevel is required, at least, to ensure the capturing of failed login events.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # sshd -T|&grep -i LogLevel

    Expected result:

     LogLevel INFO

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/ssh/sshd_config

    Ensure that the \"LogLevel\" line is uncommented and set to the following:

    LogLevel INFO

    At the command line, execute the following command:

    # systemctl restart sshd.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000032-GPOS-00013'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'PHTN-30-000008'
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']

  sshdcommand = input('sshdcommand')
  describe command("#{sshdcommand}|&grep -i loglevel") do
    its('stdout.strip') { should cmp 'loglevel INFO' }
  end
end
