control 'PHTN-30-000071' do
  title 'The Photon operating system must use the "pam_cracklib" module.'
  desc 'If the operating system allows the user to select passwords based on dictionary words, this increases the chances of password compromise by increasing the opportunity for successful guesses and brute-force attacks.'
  desc 'check', 'At the command line, run the following command:

# grep pam_cracklib /etc/pam.d/system-password

If the output does not return at least "password  requisite   pam_cracklib.so", this is a finding.'
  desc 'fix', 'Navigate to and open:

/etc/pam.d/system-password

Add the following, replacing any existing "pam_cracklib.so" line:

password requisite pam_cracklib.so dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1 minlen=8 minclass=4 difok=4 retry=3 maxsequence=0 enforce_for_root

Note: On vCenter appliances, the equivalent file must be edited under "/etc/applmgmt/appliance", if one exists, for the changes to persist after a reboot.'
  impact 0.5
  tag check_id: 'C-60216r887295_chk'
  tag severity: 'medium'
  tag gid: 'V-256541'
  tag rid: 'SV-256541r887297_rule'
  tag stig_id: 'PHTN-30-000071'
  tag gtitle: 'SRG-OS-000480-GPOS-00225'
  tag fix_id: 'F-60159r887296_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe file('/etc/pam.d/system-password') do
    its('content') { should match /^^password\s*requisite\s*pam_cracklib\.so.*$/ }
  end
end
