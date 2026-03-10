control 'PHTN-50-000035' do
  title 'The Photon operating system must enforce password complexity by requiring that at least one uppercase character be used.'
  desc  "
    Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

    Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify at least one uppercase character be used:

    # grep '^ucredit' /etc/security/pwquality.conf

    Example result:

    ucredit = -1

    If the \"ucredit\" option is not < 0, is missing or commented out, this is a finding.

    Note: If pwquality.conf is not used to configure pam_pwquality.so, these options may be specified on the pwquality line in the system-password file.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/security/pwquality.conf

    Add or update the following lines:

    ucredit = -1
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000069-GPOS-00037'
  tag gid: 'V-PHTN-50-000035'
  tag rid: 'SV-PHTN-50-000035'
  tag stig_id: 'PHTN-50-000035'
  tag cci: ['CCI-004066']
  tag nist: ['IA-5 (1) (h)']

  if input('usePwqualityConf')
    describe parse_config_file('/etc/security/pwquality.conf') do
      its('ucredit') { should cmp < 0 }
    end
  else
    describe file('/etc/pam.d/system-password') do
      its('content') { should match /^password\s+(required|requisite)\s+pam_pwquality\.so\s+(?=.*\bucredit=-1\b).*$/ }
    end
  end
end
