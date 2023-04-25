control 'VRAA-8X-000126' do
  title 'vRA must must configure sshd to limit the number of allowed login attempts per connection.'
  desc  'By setting the login attempt limit to a low value, an attacker will be forced to reconnect frequently, which severely limits the speed and effectiveness of brute-force attacks.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command:

    # sshd -T|&grep -i MaxAuthTries

    Example result:

    MaxAuthTries 6

    If the output does not match the organization-defined expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/ssh/sshd_config

    Ensure that the \"MaxAuthTries\" line is uncommented and set to the following:

    MaxAuthTries <organization-defined value>

    At the command line, execute the following command:

    # systemctl restart sshd.service

    Note: Replace <organization-defined value> with an appropriately defined value for the environment.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: 'V-VRAA-8X-000126'
  tag rid: 'SV-VRAA-8X-000126'
  tag stig_id: 'VRAA-8X-000126'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe command('sshd -T|&grep -i MaxAuthTries') do
    its('stdout.strip') { should cmp input('maxAuthTries') }
  end
end
