control 'PHTN-50-000036' do
  title 'The Photon operating system must enforce password complexity by requiring that at least one lowercase character be used.'
  desc  "
    Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

    Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify at least one lowercase character be used:

    # grep '^lcredit' /etc/security/pwquality.conf

    Example result:

    lcredit = -1

    If the \"lcredit\" option is not < 0, is missing or commented out, this is a finding.

    Note: If pwquality.conf is not used to configure pam_pwquality.so, these options may be specified on the pwquality line in the system-password file.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/security/pwquality.conf

    Add or update the following lines:

    lcredit = -1
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000070-GPOS-00038'
  tag gid: 'V-PHTN-50-000036'
  tag rid: 'SV-PHTN-50-000036'
  tag stig_id: 'PHTN-50-000036'
  tag cci: ['CCI-000193']
  tag nist: ['IA-5 (1) (a)']

  if input('usePwqualityConf')
    describe parse_config_file('/etc/security/pwquality.conf') do
      its('lcredit') { should cmp < 0 }
    end
  else
    describe file('/etc/pam.d/system-password') do
      its('content') { should match /^password\s+(required|requisite)\s+pam_pwquality\.so\s+(?=.*\blcredit=-1\b).*$/ }
    end
  end
end
