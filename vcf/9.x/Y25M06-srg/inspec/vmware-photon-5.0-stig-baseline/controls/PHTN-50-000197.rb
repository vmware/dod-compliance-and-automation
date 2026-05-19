control 'PHTN-50-000197' do
  title 'The Photon operating system must be configured to use the pam_pwquality.so module.'
  desc  "
    Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

    Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify the pam_pwquality.so module is used:

    # grep '^password' /etc/pam.d/system-password

    Example result:

    password required pam_pwhistory.so use_authtok
    password required pam_pwquality.so use_authtok
    password required pam_unix.so sha512 shadow use_authtok

    If the pam_pwquality.so module is not present, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/pam.d/system-password

    Add or update the following line:

    password required pam_pwquality.so use_authtok
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000069-GPOS-00037'
  tag gid: 'V-PHTN-50-000197'
  tag rid: 'SV-PHTN-50-000197'
  tag stig_id: 'PHTN-50-000197'
  tag cci: ['CCI-004066']
  tag nist: ['IA-5 (1) (h)']

  describe file('/etc/pam.d/system-password') do
    its('content') { should match /^password\s+(required|requisite)\s+pam_pwquality\.so\s+.*$/ }
  end
end
