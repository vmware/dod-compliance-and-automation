control 'UBTU-24-400330' do
  title 'Ubuntu 24.04 LTS must enforce password complexity by requiring that at least one special character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity or strength is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor in determining how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

Special characters are those characters that are not alphanumeric. Examples include: ~ ! @ # $ % ^ *.

'
  desc 'check', 'Determine if the field "ocredit" is set in the "/etc/security/pwquality.conf" file with the following command:

$ grep -i "ocredit" /etc/security/pwquality.conf
ocredit=-1

If the "ocredit" parameter is greater than "-1", is commented out, or is missing, this is a finding.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to enforce password complexity by requiring that at least one special character be used.

Add or update the following line in the "/etc/security/pwquality.conf" file to include the "ocredit=-1" parameter:

ocredit=-1'
  impact 0.5
  tag check_id: 'C-74766r1066686_chk'
  tag severity: 'medium'
  tag gid: 'V-270733'
  tag rid: 'SV-270733r1066688_rule'
  tag stig_id: 'UBTU-24-400330'
  tag gtitle: 'SRG-OS-000266-GPOS-00101'
  tag fix_id: 'F-74667r1066687_fix'
  tag satisfies: ['SRG-OS-000266-GPOS-00101', 'SRG-OS-000730-GPOS-00190']
  tag 'documentable'
  tag cci: ['CCI-004065', 'CCI-004066']
  tag nist: ['IA-5 (1) (g)', 'IA-5 (1) (h)']

  password_quality_file = input('password_quality_file')

  pwquality_package = package('libpam-pwquality')

  if pwquality_package.installed?
    describe parse_config_file(password_quality_file) do
      its('ocredit') { should cmp(-1) }
    end
  else
    describe pwquality_package do
      it { should be_installed }
    end
  end
end
