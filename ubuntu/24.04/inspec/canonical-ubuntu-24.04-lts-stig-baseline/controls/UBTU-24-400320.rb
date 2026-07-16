control 'UBTU-24-400320' do
  title 'Ubuntu 24.04 LTS must enforce a minimum 15-character password length.'
  desc 'The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised.

Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.

'
  desc 'check', 'Verify the pwquality configuration file enforces a minimum 15-character password length with the following command:

$ grep -i minlen /etc/security/pwquality.conf
minlen=15

If "minlen" parameter value is not "15" or higher, is commented out, or is missing, this is a finding.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to enforce a minimum 15-character password length.

Add or modify the "minlen" parameter value to the "/etc/security/pwquality.conf" file:

minlen=15'
  impact 0.5
  tag check_id: 'C-74765r1066683_chk'
  tag severity: 'medium'
  tag gid: 'V-270732'
  tag rid: 'SV-270732r1066685_rule'
  tag stig_id: 'UBTU-24-400320'
  tag gtitle: 'SRG-OS-000078-GPOS-00046'
  tag fix_id: 'F-74666r1066684_fix'
  tag satisfies: ['SRG-OS-000078-GPOS-00046', 'SRG-OS-000730-GPOS-00190']
  tag 'documentable'
  tag cci: ['CCI-004065', 'CCI-004066']
  tag nist: ['IA-5 (1) (g)', 'IA-5 (1) (h)']

  password_quality_file = input('password_quality_file')

  pwquality_package = package('libpam-pwquality')

  if pwquality_package.installed?
    describe parse_config_file(password_quality_file) do
      its('minlen') { should cmp 15 }
    end
  else
    describe pwquality_package do
      it { should be_installed }
    end
  end
end
