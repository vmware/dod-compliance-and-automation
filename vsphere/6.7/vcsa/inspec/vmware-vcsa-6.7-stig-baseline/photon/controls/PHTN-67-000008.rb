control 'PHTN-67-000008' do
  title "The Photon operating system must have the sshd LogLevel set to
\"INFO\"."
  desc  "Automated monitoring of remote access sessions allows organizations to
detect cyberattacks and ensure ongoing compliance with remote access policies
by auditing connection activities.

    The INFO LogLevel is required, at least, to ensure the capturing of failed
login events.
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
    Open /etc/ssh/sshd_config with a text editor.

    Ensure that the \"LogLevel\" line is uncommented and set to the following:

    LogLevel INFO

    At the command line, execute the following command:

    # service sshd reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000032-GPOS-00013'
  tag gid: 'V-239080'
  tag rid: 'SV-239080r675048_rule'
  tag stig_id: 'PHTN-67-000008'
  tag fix_id: 'F-42250r675047_fix'
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']

  describe command('sshd -T|&grep -i loglevel') do
    its('stdout.strip') { should cmp 'loglevel INFO' }
  end
end
