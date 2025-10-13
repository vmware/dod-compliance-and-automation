control 'PHTN-50-000264' do
  title 'The Photon operating system must ensure the password complexity module in the system-auth file is configured for three retries or less.'
  desc  "
    Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. \"pwquality\" enforces complex password construction configuration and has the ability to limit brute-force attacks on the system.

    By limiting the number of attempts to meet the pwquality module complexity requirements before returning with an error, the system will audit abnormal attempts at password changes.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify that the \"pwquality\" retry option is set to \"3\":

    # grep '^retry' /etc/security/pwquality.conf

    Example result:

    retry = 3

    If the value of \"retry\" is set to \"0\", is greater than \"3\", or is missing, this is a finding.

    Note: If pwquality.conf is not used to configure pam_pwquality.so, these options may be specified on the pwquality line in the system-password file.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/security/pwquality.conf

    Add or update the following lines:

    retry = 3
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-PHTN-50-000264'
  tag rid: 'SV-PHTN-50-000264'
  tag stig_id: 'PHTN-50-000264'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  if input('usePwqualityConf')
    describe parse_config_file('/etc/security/pwquality.conf') do
      its('retry') { should cmp > 0 }
      its('retry') { should cmp <= 3 }
    end
  else
    describe file('/etc/pam.d/system-password') do
      its('content') { should match(/^password\s+(required|requisite)\s+pam_pwquality\.so\s+(?=.*\bretry=(?:[1-3])\b).*$/) }
    end
  end
end
