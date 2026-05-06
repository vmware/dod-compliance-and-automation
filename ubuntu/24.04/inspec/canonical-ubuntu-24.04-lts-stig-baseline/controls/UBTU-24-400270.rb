control 'UBTU-24-400270' do
  title 'Ubuntu 24.04 LTS must enforce password complexity by requiring that at least one lowercase character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

'
  desc 'check', 'Verify Ubuntu 24.04 LTS enforces password complexity by requiring that at least one lowercase character be used with the following command:

$ grep -i "lcredit" /etc/security/pwquality.conf
lcredit=-1

If the "lcredit" parameter is greater than "-1", is commented out, or is missing, this is a finding.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to enforce password complexity by requiring that at least one lowercase character be used.

Add or update the "/etc/security/pwquality.conf" file to contain the "lcredit" parameter:

lcredit=-1'
  impact 0.5
  tag check_id: 'C-74760r1066668_chk'
  tag severity: 'medium'
  tag gid: 'V-270727'
  tag rid: 'SV-270727r1066670_rule'
  tag stig_id: 'UBTU-24-400270'
  tag gtitle: 'SRG-OS-000070-GPOS-00038'
  tag fix_id: 'F-74661r1066669_fix'
  tag satisfies: ['SRG-OS-000070-GPOS-00038', 'SRG-OS-000730-GPOS-00190']
  tag 'documentable'
  tag cci: ['CCI-004065', 'CCI-004066']
  tag nist: ['IA-5 (1) (g)', 'IA-5 (1) (h)']

  password_quality_file = input('password_quality_file')

  pwquality_package = package('libpam-pwquality')

  if pwquality_package.installed?
    describe parse_config_file(password_quality_file) do
      its('lcredit') { should cmp(-1) }
    end
  else
    describe pwquality_package do
      it { should be_installed }
    end
  end
end
