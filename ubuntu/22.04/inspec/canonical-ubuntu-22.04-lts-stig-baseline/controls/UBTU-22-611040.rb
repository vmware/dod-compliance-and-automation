control 'UBTU-22-611040' do
  title 'Ubuntu 22.04 LTS must require the change of at least eight characters when passwords are changed.'
  desc 'If the operating system allows the user to consecutively reuse extensive portions of passwords, this increases the chances of password compromise by increasing the window of opportunity for attempts at guessing and brute-force attacks.

The number of changed characters refers to the number of changes required with respect to the total number of positions in the current password. In other words, characters may be the same within the two passwords; however, the positions of the like characters must be different.

If the password length is an odd number then number of changed characters must be rounded up. For example, a password length of 15 characters must require the change of at least eight characters.'
  desc 'check', 'Verify Ubuntu 22.04 LTS requires the change of at least eight characters when passwords are changed by using the following command:

     $ grep -i difok /etc/security/pwquality.conf
     difok = 8

If "difok" is less than "8", is commented out, or is missing, this is a finding.'
  desc 'fix', 'Configure Ubuntu 22.04 LTS to require the change of at least eight characters when passwords are changed.

Add or modify the following line in the "/etc/security/pwquality.conf" file:

difok = 8'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64295r953509_chk'
  tag severity: 'medium'
  tag gid: 'V-260566'
  tag rid: 'SV-260566r1015017_rule'
  tag stig_id: 'UBTU-22-611040'
  tag gtitle: 'SRG-OS-000072-GPOS-00040'
  tag fix_id: 'F-64203r953510_fix'
  tag 'documentable'
  tag cci: ['CCI-000195', 'CCI-004066']
  tag nist: ['IA-5 (1) (b)', 'IA-5 (1) (h)']

  config_file = '/etc/security/pwquality.conf'
  config_file_exists = file(config_file).exist?

  if config_file_exists
    describe parse_config_file(config_file) do
      its('difok') { should cmp >= 8 }
    end
  else
    describe("#{config_file} exists") do
      subject { config_file_exists }
      it { should be true }
    end
  end
end
