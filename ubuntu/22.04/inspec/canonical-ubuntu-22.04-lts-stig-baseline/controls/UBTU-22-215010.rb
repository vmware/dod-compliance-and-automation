control 'UBTU-22-215010' do
  title 'Ubuntu 22.04 LTS must have the "libpam-pwquality" package installed.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. "pwquality" enforces complex password construction configuration and has the ability to limit brute-force attacks on the system.'
  desc 'check', 'Verify Ubuntu 22.04 LTS has the "libpam-pwquality" package installed with  the following command:

     $ dpkg -l | grep libpam-pwquality
     ii     libpam-pwquality:amd64     1.4.4-1build2     amd64     PAM module to check password strength

If "libpam-pwquality" is not installed, this is a finding.'
  desc 'fix', 'Install the "pam_pwquality" package by using the following command:

     $ sudo apt-get install libpam-pwquality'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64207r953245_chk'
  tag severity: 'medium'
  tag gid: 'V-260478'
  tag rid: 'SV-260478r991587_rule'
  tag stig_id: 'UBTU-22-215010'
  tag gtitle: 'SRG-OS-000480-GPOS-00225'
  tag fix_id: 'F-64115r953246_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe package('libpam-pwquality') do
    it { should be_installed }
  end
end
