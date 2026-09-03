control 'PHTN-50-000038' do
  title 'The Photon operating system must require the change of at least eight characters when passwords are changed.'
  desc  "
     If the operating system allows the user to consecutively reuse extensive portions of passwords, this increases the chances of password compromise by increasing the window of opportunity for attempts at guessing and brute-force attacks.

    The number of changed characters refers to the number of changes required with respect to the total number of positions in the current password. In other words, characters may be the same within the two passwords; however, the positions of the like characters must be different.

    If the password length is an odd number then number of changed characters must be rounded up. For example, a password length of 15 characters must require the change of at least eight characters.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify at least eight different characters be used:

    # grep '^difok' /etc/security/pwquality.conf

    Example result:

    difok = 8

    If the \"difok\" option is not >= 8, is missing or commented out, this is a finding.

    Note: If pwquality.conf is not used to configure pam_pwquality.so, these options may be specified on the pwquality line in the system-password file.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/security/pwquality.conf

    Add or update the following lines:

    difok = 8
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000072-GPOS-00040'
  tag gid: 'V-PHTN-50-000038'
  tag rid: 'SV-PHTN-50-000038'
  tag stig_id: 'PHTN-50-000038'
  tag cci: ['CCI-004066']
  tag nist: ['IA-5 (1) (h)']

  if input('usePwqualityConf')
    describe parse_config_file('/etc/security/pwquality.conf') do
      its('difok') { should cmp >= 8 }
    end
  else
    describe file('/etc/pam.d/system-password') do
      its('content') { should match /^password\s+(required|requisite)\s+pam_pwquality\.so\s+(?=.*\bdifok=8\b).*$/ }
    end
  end
end
