control 'UBTU-24-300014' do
  title 'Ubuntu 24.04 LTS must prevent the use of dictionary words for passwords.'
  desc 'Password-based authentication applies to passwords regardless of whether they are used in single-factor or multifactor authentication. Long passwords or passphrases are preferable over shorter passwords. Enforced composition rules provide marginal security benefits while decreasing usability. However, organizations may choose to establish certain rules for password generation (e.g., minimum character length for long passwords) under certain circumstances and can enforce this requirement in IA-5(1)(h). Account recovery can occur, for example, in situations when a password is forgotten. Cryptographically protected passwords include salted one-way cryptographic hashes of passwords. The list of commonly used, compromised, or expected passwords includes passwords obtained from previous breach corpuses, dictionary words, and repetitive or sequential characters. The list includes context-specific words, such as the name of the service, username, and derivatives thereof.'
  desc 'check', 'Verify Ubuntu 24.04 LTS uses the "cracklib" library to prevent the use of dictionary words with the following command:

$ grep dictcheck /etc/security/pwquality.conf
dictcheck=1

If the "dictcheck" parameter is not set to "1" or is commented out, this is a finding.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to prevent the use of dictionary words for passwords.

Add or update the following line in the "/etc/security/pwquality.conf" file to include the "dictcheck=1" parameter:

dictcheck=1'
  impact 0.5
  tag check_id: 'C-74737r1066599_chk'
  tag severity: 'medium'
  tag gid: 'V-270704'
  tag rid: 'SV-270704r1066601_rule'
  tag stig_id: 'UBTU-24-300014'
  tag gtitle: 'SRG-OS-000710-GPOS-00160'
  tag fix_id: 'F-74638r1066600_fix'
  tag 'documentable'
  tag cci: ['CCI-004061']
  tag nist: ['IA-5 (1) (b)']

  password_quality_file = input('password_quality_file')

  pwquality_package = package('libpam-pwquality')

  if pwquality_package.installed?
    describe parse_config_file(password_quality_file) do
      its('dictcheck') { should cmp 1 }
    end
  else
    describe pwquality_package do
      it { should be_installed }
    end
  end
end
