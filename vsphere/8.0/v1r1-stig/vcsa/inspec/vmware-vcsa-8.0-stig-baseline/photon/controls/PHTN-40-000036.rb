control 'PHTN-40-000036' do
  title 'The Photon operating system must enforce password complexity by requiring that at least one lowercase character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', %q(At the command line, run the following command to verify at least one lowercase character be used:

# grep '^password.*pam_pwquality.so' /etc/pam.d/system-password

Example result:

password  requisite   pam_pwquality.so  dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1 minlen=15 difok=8 enforce_for_root dictcheck=1

If the "lcredit" option is not < 0, is missing or commented out, this is a finding.)
  desc 'fix', 'Navigate to and open:

/etc/pam.d/system-password

Configure the pam_pwquality.so line to have the "lcredit" option set to "-1" as follows:

password  requisite   pam_pwquality.so  dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1 minlen=15 difok=8 enforce_for_root dictcheck=1

Note: On vCenter appliances, the equivalent file must be edited under "/etc/applmgmt/appliance", if one exists, for the changes to persist after a reboot.'
  impact 0.5
  tag check_id: 'C-62555r933504_chk'
  tag severity: 'medium'
  tag gid: 'V-258815'
  tag rid: 'SV-258815r933506_rule'
  tag stig_id: 'PHTN-40-000036'
  tag gtitle: 'SRG-OS-000070-GPOS-00038'
  tag fix_id: 'F-62464r933505_fix'
  tag cci: ['CCI-000193']
  tag nist: ['IA-5 (1) (a)']

  if input('usePwqualityConf')
    describe parse_config_file('/etc/security/pwquality.conf') do
      its('lcredit') { should cmp < 0 }
    end
  else
    describe file('/etc/pam.d/system-password') do
      its('content') { should match /^password\s+(required|requisite)\s+pam_pwquality\.so\s+(?=.*\blcredit=-1\b).*$/ }
    end
  end
end
