control 'PHTN-50-000263' do
  title 'The Photon operating system must require the change of at least four character classes when passwords are changed.'
  desc  "
    Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

    Password complexity is one factor of several that determines how long it takes to crack a password. The more complex a password, the greater the number of possible combinations that need to be tested before the password is compromised.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify that passwords contain at least four character classes:

    # grep '^minclass' /etc/security/pwquality.conf

    Example result:

    minclass = 4

    If the value of \"minclass\" is set to less than \"4\", or is commented out, this is a finding.

    Note: If pwquality.conf is not used to configure pam_pwquality.so, these options may be specified on the pwquality line in the system-password file.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/security/pwquality.conf

    Add or update the following lines:

    minclass = 4
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-PHTN-50-000263'
  tag rid: 'SV-PHTN-50-000263'
  tag stig_id: 'PHTN-50-000263'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  if input('usePwqualityConf')
    describe parse_config_file('/etc/security/pwquality.conf') do
      its('minclass') { should cmp >= 4 }
    end
  else
    describe file('/etc/pam.d/system-password') do
      its('content') { should match(/^password\s+(required|requisite)\s+pam_pwquality\.so\s+(?=.*\bminclass=([4-9]|\d{2,})\b).*$/) }
    end
  end
end
