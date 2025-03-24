control 'PHTN-40-000243' do
  title 'The Photon operating system must be configured to use the pam_pwhistory.so module.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed as per policy requirements.'
  desc 'check', %q(At the command line, run the following command to verify the pam_pwhistory.so module is used:

# grep '^password' /etc/pam.d/system-password

Example result:

password  requisite   pam_pwquality.so  dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1 minlen=15 difok=8 enforce_for_root dictcheck=1
password  required    pam_pwhistory.so  remember=5 retry=3 enforce_for_root use_authtok
password  required    pam_unix.so       sha512 use_authtok shadow try_first_pass

If the "pam_pwhistory.so" module is not present, this is a finding.
If "use_authtok" is not present for the "pam_pwhistory.so" module, this is a finding.
If "conf" or "file" are present for the "pam_pwhistory.so" module, this is a finding.)
  desc 'fix', 'Navigate to and open:

/etc/pam.d/system-password

Add or update the pam_pwhistory.so module line as follows:

password  required    pam_pwhistory.so  remember=5 retry=3 enforce_for_root use_authtok

Note: The line must be configured after pam_pwquality.so.

Note: On vCenter appliances, the equivalent file must be edited under "/etc/applmgmt/appliance", if one exists, for the changes to persist after a reboot.'
  impact 0.5
  tag check_id: 'C-62642r933765_chk'
  tag severity: 'medium'
  tag gid: 'V-258902'
  tag rid: 'SV-258902r1003655_rule'
  tag stig_id: 'PHTN-40-000243'
  tag gtitle: 'SRG-OS-000077-GPOS-00045'
  tag fix_id: 'F-62551r933766_fix'
  tag cci: ['CCI-004061']
  tag nist: ['IA-5 (1) (b)']

  describe file('/etc/pam.d/system-password') do
    its('content') { should match /^password\s+(required|requisite)\s+pam_pwhistory\.so\s+(?=.*\buse_authtok\b).*$/ }
    its('content') { should_not match /^password\s+(required|requisite)\s+pam_pwhistory\.so\s+(?=.*\bconf\b).*$/ }
    its('content') { should_not match /^password\s+(required|requisite)\s+pam_pwhistory\.so\s+(?=.*\bfile\b).*$/ }
  end
end
