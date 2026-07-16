control 'UBTU-24-400280' do
  title 'Ubuntu 24.04 LTS must enforce password complexity by requiring that at least one numeric character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

'
  desc 'check', 'Verify Ubuntu 24.04 LTS enforces password complexity by requiring that at least one numeric character be used.

Determine if the field "dcredit" is set in the "/etc/security/pwquality.conf" file with the following command:

$ grep -i "dcredit" /etc/security/pwquality.conf
dcredit=-1

If the "dcredit" parameter is greater than "-1", is commented out, or is missing, this is a finding.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to enforce password complexity by requiring that at least one numeric character be used.

Add or update the "/etc/security/pwquality.conf" file to contain the "dcredit" parameter:

dcredit=-1'
  impact 0.5
  tag check_id: 'C-74761r1066671_chk'
  tag severity: 'medium'
  tag gid: 'V-270728'
  tag rid: 'SV-270728r1066673_rule'
  tag stig_id: 'UBTU-24-400280'
  tag gtitle: 'SRG-OS-000071-GPOS-00039'
  tag fix_id: 'F-74662r1066672_fix'
  tag satisfies: ['SRG-OS-000071-GPOS-00039', 'SRG-OS-000730-GPOS-00190']
  tag 'documentable'
  tag cci: ['CCI-004065', 'CCI-004066']
  tag nist: ['IA-5 (1) (g)', 'IA-5 (1) (h)']

  password_quality_file = input('password_quality_file')

  pwquality_package = package('libpam-pwquality')

  if pwquality_package.installed?
    describe parse_config_file(password_quality_file) do
      its('dcredit') { should cmp(-1) }
    end
  else
    describe pwquality_package do
      it { should be_installed }
    end
  end
end
