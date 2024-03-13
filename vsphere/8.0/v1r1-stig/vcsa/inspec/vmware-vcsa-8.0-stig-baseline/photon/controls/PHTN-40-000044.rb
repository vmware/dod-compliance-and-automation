control 'PHTN-40-000044' do
  title 'The Photon operating system must enforce a minimum 15-character password length.'
  desc 'The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised.

Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.'
  desc 'check', %q(At the command line, run the following command to verify a minimum 15-character password length:

# grep '^password.*pam_pwquality.so' /etc/pam.d/system-password

Example result:

password  requisite   pam_pwquality.so  dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1 minlen=15 difok=8 enforce_for_root dictcheck=1

If the "minlen" option is not >= 15, is missing or commented out, this is a finding.)
  desc 'fix', 'Navigate to and open:

/etc/pam.d/system-password

Configure the pam_pwquality.so line to have the "minlen" option set to "15" as follows:

password  requisite   pam_pwquality.so  dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1 minlen=15 difok=8 enforce_for_root dictcheck=1

Note: On vCenter appliances, the equivalent file must be edited under "/etc/applmgmt/appliance", if one exists, for the changes to persist after a reboot.'
  impact 0.5
  tag check_id: 'C-62563r933528_chk'
  tag severity: 'medium'
  tag gid: 'V-258823'
  tag rid: 'SV-258823r933530_rule'
  tag stig_id: 'PHTN-40-000044'
  tag gtitle: 'SRG-OS-000078-GPOS-00046'
  tag fix_id: 'F-62472r933529_fix'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']

  if input('usePwqualityConf')
    describe parse_config_file('/etc/security/pwquality.conf') do
      its('minlen') { should cmp > 14 }
    end
  else
    describe file('/etc/pam.d/system-password') do
      its('content') { should match /^password\s+(required|requisite)\s+pam_pwquality\.so\s+(?=.*\bminlen=15\b).*$/ }
    end
  end
end
