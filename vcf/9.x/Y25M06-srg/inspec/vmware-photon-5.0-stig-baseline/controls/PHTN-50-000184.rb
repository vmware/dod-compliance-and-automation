control 'PHTN-50-000184' do
  title 'The Photon operating system must prevent the use of dictionary words for passwords.'
  desc  'If the operating system allows the user to select passwords based on dictionary words, then this increases the chances of password compromise by increasing the opportunity for successful guesses and brute-force attacks.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify passwords do not match dictionary words:

    # grep '^dictcheck' /etc/security/pwquality.conf

    Example result:

    dictcheck = 1

    If the \"dictcheck\" option is not set to 1, is missing or commented out, this is a finding.

    Note: If pwquality.conf is not used to configure pam_pwquality.so, these options may be specified on the pwquality line in the system-password file.
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
  tag satisfies: ['SRG-OS-000710-GPOS-00160']
  tag gid: 'V-PHTN-50-000184'
  tag rid: 'SV-PHTN-50-000184'
  tag stig_id: 'PHTN-50-000184'
  tag cci: ['CCI-000366', 'CCI-004061']
  tag nist: ['CM-6 b', 'IA-5 (1) (b)']

  if input('usePwqualityConf')
    describe parse_config_file('/etc/security/pwquality.conf') do
      its('dictcheck') { should cmp 1 }
    end
  else
    describe file('/etc/pam.d/system-password') do
      its('content') { should match /^password\s+(required|requisite)\s+pam_pwquality\.so\s+(?=.*\bdictcheck=1\b).*$/ }
    end
  end
end
