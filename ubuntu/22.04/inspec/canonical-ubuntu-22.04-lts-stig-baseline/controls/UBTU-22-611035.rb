control 'UBTU-22-611035' do
  title 'Ubuntu 22.04 LTS must enforce a minimum 15-character password length.'
  desc 'The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised.

Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.'
  desc 'check', 'Verify the pwquality configuration file enforces a minimum 15-character password length by using the following command:

     $ grep -i minlen /etc/security/pwquality.conf
     minlen = 15

If "minlen" is not "15" or higher, is commented out, or is missing, this is a finding.'
  desc 'fix', 'Configure Ubuntu 22.04 LTS to enforce a minimum 15-character password length.

Add or modify the following line in the "/etc/security/pwquality.conf" file:

minlen = 15'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64294r953506_chk'
  tag severity: 'medium'
  tag gid: 'V-260565'
  tag rid: 'SV-260565r1015016_rule'
  tag stig_id: 'UBTU-22-611035'
  tag gtitle: 'SRG-OS-000078-GPOS-00046'
  tag fix_id: 'F-64202r953507_fix'
  tag 'documentable'
  tag cci: ['CCI-000205', 'CCI-004066']
  tag nist: ['IA-5 (1) (a)', 'IA-5 (1) (h)']

  config_file = '/etc/security/pwquality.conf'
  config_file_exists = file(config_file).exist?

  if config_file_exists
    describe parse_config_file(config_file) do
      its('minlen') { should cmp >= 15 }
    end
  else
    describe("#{config_file} exists") do
      subject { config_file_exists }
      it { should be true }
    end
  end
end
