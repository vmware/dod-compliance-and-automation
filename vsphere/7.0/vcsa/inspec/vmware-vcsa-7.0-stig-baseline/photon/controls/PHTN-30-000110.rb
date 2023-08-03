control 'PHTN-30-000110' do
  title 'The Photon operating system must enforce password complexity on the root account.'
  desc 'Password complexity rules must apply to all accounts on the system, including root. Without specifying the "enforce_for_root flag", "pam_cracklib" does not apply complexity rules to the root user. While root users can find ways around this requirement, given its superuser power, it is necessary to attempt to force compliance.'
  desc 'check', 'At the command line, run the following command:

# grep pam_cracklib /etc/pam.d/system-password|grep --color=always "enforce_for_root"

Expected result:

password requisite pam_cracklib.so dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1 minlen=8 minclass=4 difok=4 retry=3 maxsequence=0 enforce_for_root

If the output does not include "enforce_for_root", this is a finding.'
  desc 'fix', 'Navigate to and open:

/etc/pam.d/system-password

Add the following, replacing any existing "pam_cracklib.so" line:

password requisite pam_cracklib.so dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1 minlen=8 minclass=4 difok=4 retry=3 maxsequence=0 enforce_for_root

Note: On vCenter appliances, the equivalent file must be edited under "/etc/applmgmt/appliance", if one exists, for the changes to persist after a reboot.'
  impact 0.5
  tag check_id: 'C-60254r887409_chk'
  tag severity: 'medium'
  tag gid: 'V-256579'
  tag rid: 'SV-256579r887411_rule'
  tag stig_id: 'PHTN-30-000110'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-60197r887410_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe file('/etc/pam.d/system-password') do
    its('content') { should match /^password\s*requisite\s*pam_cracklib\.so\s*(?=.*\benforce_for_root\b).*$/ }
  end
end
