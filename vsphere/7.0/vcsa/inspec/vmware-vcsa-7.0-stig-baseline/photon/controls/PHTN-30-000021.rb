control 'PHTN-30-000021' do
  title 'The Photon operating system must enforce password complexity by requiring that at least one uppercase character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.'
  desc 'check', 'At the command line, run the following command:

# grep pam_cracklib /etc/pam.d/system-password|grep --color=always "ucredit=.."

Expected result:

password requisite pam_cracklib.so dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1 minlen=8 minclass=4 difok=4 retry=3 maxsequence=0 enforce_for_root

If the output does not include ucredit= <= -1, this is a finding.'
  desc 'fix', 'Navigate to and open:

/etc/pam.d/system-password

Add the following, replacing any existing "pam_cracklib.so" line:

password requisite pam_cracklib.so dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1 minlen=8 minclass=4 difok=4 retry=3 maxsequence=0 enforce_for_root

Note: On vCenter appliances, the equivalent file must be edited under "/etc/applmgmt/appliance", if one exists, for the changes to persist after a reboot.'
  impact 0.5
  tag check_id: 'C-60173r887166_chk'
  tag severity: 'medium'
  tag gid: 'V-256498'
  tag rid: 'SV-256498r887168_rule'
  tag stig_id: 'PHTN-30-000021'
  tag gtitle: 'SRG-OS-000069-GPOS-00037'
  tag fix_id: 'F-60116r887167_fix'
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']

  describe file('/etc/pam.d/system-password') do
    its('content') { should match /^password\s*requisite\s*pam_cracklib\.so\s*(?=.*\bucredit=-1\b).*$/ }
  end
end
