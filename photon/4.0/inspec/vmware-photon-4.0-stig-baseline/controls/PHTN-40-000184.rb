control 'PHTN-40-000184' do
  title 'The Photon operating system must prevent the use of dictionary words for passwords.'
  desc  'If the operating system allows the user to select passwords based on dictionary words, then this increases the chances of password compromise by increasing the opportunity for successful guesses and brute-force attacks.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify at least one upper-case character be used:

    # grep dictcheck /etc/security/pwquality.conf

    Expected result:

    dictcheck = 1

    If the \"dictcheck\" option is 1, is missing or commented out, this is a finding.

    Note: If pwquality.conf is not used to configure pam_pwquality.so then these options may be specified on the pwquality line in system-password file.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/security/pwquality.conf

    Add or update the following lines:

    dictcheck = 1
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00225'
  tag gid: 'V-PHTN-40-000184'
  tag rid: 'SV-PHTN-40-000184'
  tag stig_id: 'PHTN-40-000184'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  if input('usePwqualityConf')
    describe parse_config_file('/etc/security/pwquality.conf') do
      its('dictcheck') { should cmp 1 }
    end
  else
    describe pam('/etc/pam.d/system-password') do
      its('lines') { should match_pam_rule('password required pam_pwquality.so') }
      its('lines') { should match_pam_rule('password required pam_pwquality.so').all_with_integer_arg('dictcheck', '==', 1) }
    end
  end
end
