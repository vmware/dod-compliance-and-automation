control 'UBTU-24-400290' do
  title 'Ubuntu 24.04 LTS must require the change of at least eight characters when passwords are changed.'
  desc 'If Ubuntu 24.04 LTS allows the user to consecutively reuse extensive portions of passwords, this increases the chances of password compromise by increasing the window of opportunity for attempts at guessing and brute-force attacks.

The number of changed characters refers to the number of changes required with respect to the total number of positions in the current password. In other words, characters may be the same within the two passwords; however, the positions of the like characters must be different.

If the password length is an odd number, then number of changed characters must be rounded up. For example, a password length of 15 characters must require the change of at least eight characters.

'
  desc 'check', 'Verify Ubuntu 24.04 LTS requires the change of at least eight characters when passwords are changed with the following command:

$ grep -i "difok" /etc/security/pwquality.conf
difok=8

If the "difok" parameter is less than "8" or is commented out, this is a finding.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to require the change of at least eight characters when passwords are changed.

Add or update the "/etc/security/pwquality.conf" file to include the "difok=8" parameter:

difok=8'
  impact 0.5
  tag check_id: 'C-74762r1066674_chk'
  tag severity: 'medium'
  tag gid: 'V-270729'
  tag rid: 'SV-270729r1066676_rule'
  tag stig_id: 'UBTU-24-400290'
  tag gtitle: 'SRG-OS-000072-GPOS-00040'
  tag fix_id: 'F-74663r1066675_fix'
  tag satisfies: ['SRG-OS-000072-GPOS-00040', 'SRG-OS-000730-GPOS-00190']
  tag 'documentable'
  tag cci: ['CCI-004065', 'CCI-004066']
  tag nist: ['IA-5 (1) (g)', 'IA-5 (1) (h)']

  password_quality_file = input('password_quality_file')

  pwquality_package = package('libpam-pwquality')

  if pwquality_package.installed?
    describe parse_config_file(password_quality_file) do
      its('difok') { should cmp 8 }
    end
  else
    describe pwquality_package do
      it { should be_installed }
    end
  end
end
