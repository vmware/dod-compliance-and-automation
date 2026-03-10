control 'UBTU-22-611020' do
  title 'Ubuntu 22.04 LTS must enforce password complexity by requiring that at least one numeric character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', 'Verify Ubuntu 22.04 LTS enforces password complexity by requiring that at least one numeric character be used by using the following command:

     $ grep -i dcredit /etc/security/pwquality.conf
     dcredit = -1

If "dcredit" is greater than "-1", is commented out, or is missing, this is a finding.'
  desc 'fix', 'Configure Ubuntu 22.04 LTS to enforce password complexity by requiring that at least one numeric character be used.

Add or modify the following line in the "/etc/security/pwquality.conf" file:

dcredit = -1'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64291r953497_chk'
  tag severity: 'medium'
  tag gid: 'V-260562'
  tag rid: 'SV-260562r1015014_rule'
  tag stig_id: 'UBTU-22-611020'
  tag gtitle: 'SRG-OS-000071-GPOS-00039'
  tag fix_id: 'F-64199r953498_fix'
  tag 'documentable'
  tag cci: ['CCI-000194', 'CCI-004066']
  tag nist: ['IA-5 (1) (a)', 'IA-5 (1) (h)']

  config_file = '/etc/security/pwquality.conf'
  config_file_exists = file(config_file).exist?

  if config_file_exists
    describe parse_config_file(config_file) do
      its('dcredit') { should cmp(-1) }
    end
  else
    describe("#{config_file} exists") do
      subject { config_file_exists }
      it { should be true }
    end
  end
end
