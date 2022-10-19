control 'PHTN-30-000030' do
  title 'The Photon operating system must enforce a minimum eight-character password length.'
  desc  "
    The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised.

    Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # grep pam_cracklib /etc/pam.d/system-password|grep --color=always \"minlen=..\"

    Example result:

    password requisite pam_cracklib.so dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1 minlen=8 minclass=4 difok=4 retry=3 maxsequence=0 enforce_for_root

    If the output does not include minlen >= 8, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/pam.d/system-password

    Add the following, replacing any existing \"pam_cracklib.so\" line:

    password requisite pam_cracklib.so dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1 minlen=8 minclass=4 difok=4 retry=3 maxsequence=0 enforce_for_root

    Note: On vCenter appliances you must edit the equivalent file under /etc/applmgmt/appliance if one exists for the changes to persist after a reboot.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000078-GPOS-00046'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'PHTN-30-000030'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']

  describe file('/etc/pam.d/system-password') do
    its('content') { should match /^password\s*requisite\s*pam_cracklib\.so\s*(?=.*\bminlen=8\b).*$/ }
  end
end
