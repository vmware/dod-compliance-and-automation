control 'PHTN-30-000024' do
  title 'The Photon operating system must require that new passwords are at least four characters different from the old password.'
  desc  'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # grep pam_cracklib /etc/pam.d/system-password|grep --color=always \"difok=.\"

    Expected result:

    password requisite pam_cracklib.so dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1 minlen=8 minclass=4 difok=4 retry=3 maxsequence=0 enforce_for_root

    If the output does not include difok >= 4, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/pam.d/system-password

    Add the following, replacing any existing \"pam_cracklib.so\" line :

    password requisite pam_cracklib.so dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1 minlen=8 minclass=4 difok=4 retry=3 maxsequence=0 enforce_for_root

    Note: On vCenter appliances you must edit the equivalent file under /etc/applmgmt/appliance if one exists for the changes to persist after a reboot.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000072-GPOS-00040'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'PHTN-30-000024'
  tag cci: ['CCI-000195']
  tag nist: ['IA-5 (1) (b)']

  describe file('/etc/pam.d/system-password') do
    its('content') { should match /^password\s*requisite\s*pam_cracklib\.so\s*(?=.*\bdifok=4\b).*$/ }
  end
end
