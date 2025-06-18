control 'UBTU-22-611045' do
  title 'Ubuntu 22.04 LTS must be configured so that when passwords are changed or new passwords are established, pwquality must be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. "pwquality" enforces complex password construction configuration and has the ability to limit brute-force attacks on the system.'
  desc 'check', 'Verify Ubuntu 22.04 LTS enforces password complexity rules by using the following command:

     $ grep -i enforcing /etc/security/pwquality.conf
     enforcing = 1

If "enforcing" is not "1", is commented out, or is missing, this is a finding.

Check for the use of "pwquality" by using the following command:

     $ cat /etc/pam.d/common-password | grep requisite | grep pam_pwquality
      password     requisite     pam_pwquality.so retry=3

If "retry" is set to "0" or is greater than "3", or is missing, this is a finding.'
  desc 'fix', 'Configure Ubuntu 22.04 LTS to enforce password complexity rules.

Add or modify the following line in the "/etc/security/pwquality.conf" file:

enforcing = 1

Add or modify the following line in the "/etc/pam.d/common-password" file:

password requisite pam_pwquality.so retry=3

Note: The value of "retry" should be between "1" and "3".'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64296r953512_chk'
  tag severity: 'medium'
  tag gid: 'V-260567'
  tag rid: 'SV-260567r991587_rule'
  tag stig_id: 'UBTU-22-611045'
  tag gtitle: 'SRG-OS-000480-GPOS-00225'
  tag fix_id: 'F-64204r953513_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe package('libpam-pwquality') do
    it { should be_installed }
  end

  describe file('/etc/security/pwquality.conf') do
    its('content') { should match '^enforcing\s+=\s+1$' }
  end

  describe file('/etc/pam.d/common-password') do
    its('content') { should match '^password\s+requisite\s+pam_pwquality.so\s+retry=3$' }
  end
end
