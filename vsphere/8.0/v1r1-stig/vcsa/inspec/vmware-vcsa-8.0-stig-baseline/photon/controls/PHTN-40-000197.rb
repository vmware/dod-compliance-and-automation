control 'PHTN-40-000197' do
  title 'The Photon operating system must be configured to use the pam_pwquality.so module.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', "At the command line, run the following command to verify the pam_pwquality.so module is used:

# grep '^password' /etc/pam.d/system-password

Example result:

password  requisite   pam_pwquality.so  dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1 minlen=15 difok=8 enforce_for_root dictcheck=1
password  required    pam_pwhistory.so  remember=5 retry=3 enforce_for_root use_authtok
password  required    pam_unix.so       sha512 use_authtok shadow try_first_pass

If the pam_pwquality.so module is not present, this is a finding."
  desc 'fix', 'Navigate to and open:

/etc/pam.d/system-password

Add or update the pam_pwquality.so module line as follows:

password  requisite   pam_pwquality.so  dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1 minlen=15 difok=8 enforce_for_root dictcheck=1

Note: The line must be configured before pam_pwhistory.so.

Note: On vCenter appliances, the equivalent file must be edited under "/etc/applmgmt/appliance", if one exists, for the changes to persist after a reboot.'
  impact 0.5
  tag check_id: 'C-62603r933648_chk'
  tag severity: 'medium'
  tag gid: 'V-258863'
  tag rid: 'SV-258863r933650_rule'
  tag stig_id: 'PHTN-40-000197'
  tag gtitle: 'SRG-OS-000069-GPOS-00037'
  tag fix_id: 'F-62512r933649_fix'
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']

  describe file('/etc/pam.d/system-password') do
    its('content') { should match /^password\s+(required|requisite)\s+pam_pwquality\.so\s+.*$/ }
  end
end
