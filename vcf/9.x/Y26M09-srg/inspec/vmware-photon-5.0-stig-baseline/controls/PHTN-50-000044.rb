control 'PHTN-50-000044' do
  title 'The Photon operating system must enforce a minimum 15-character password length.'
  desc  "
    The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised.

    Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify a minimum 15-character password length:

    # grep '^minlen' /etc/security/pwquality.conf

    Example result:

    minlen = 15

    If the \"minlen\" option is not >= 15, is missing or commented out, this is a finding.

    Note: If pwquality.conf is not used to configure pam_pwquality.so, these options may be specified on the pwquality line in the system-password file.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/security/pwquality.conf

    Add or update the following lines:

    minlen = 15
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000078-GPOS-00046'
  tag gid: 'V-PHTN-50-000044'
  tag rid: 'SV-PHTN-50-000044'
  tag stig_id: 'PHTN-50-000044'
  tag cci: ['CCI-004066']
  tag nist: ['IA-5 (1) (h)']

  if input('usePwqualityConf')
    describe parse_config_file('/etc/security/pwquality.conf') do
      its('minlen') { should cmp > 14 }
    end
  else
    describe file('/etc/pam.d/system-password') do
      its('content') { should match /^password\s+(required|requisite)\s+pam_pwquality\.so\s+(?=.*\bminlen=15\b).*$/ }
    end
  end
end
