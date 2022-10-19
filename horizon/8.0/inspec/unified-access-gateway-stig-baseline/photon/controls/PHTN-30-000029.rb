control 'PHTN-30-000029' do
  title 'The Photon operating system must prohibit password reuse for a minimum of five generations.'
  desc  'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed as per policy requirements.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # grep pam_pwhistory /etc/pam.d/system-password|grep --color=always \"remember=.\"

    Expected result:

    password requisite pam_pwhistory.so enforce_for_root use_authtok remember=5 retry=3

    If the output does include the \"remember=5\" setting as shown in the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/pam.d/system-password

    Add the following line after the \"password requisite pam_cracklib.so\" statement:

    password requisite pam_pwhistory.so enforce_for_root use_authtok remember=5 retry=3

    Note: On vCenter appliances you must edit the equivalent file under /etc/applmgmt/appliance if one exists for the changes to persist after a reboot.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000077-GPOS-00045'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'PHTN-30-000029'
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']

  describe file('/etc/pam.d/system-password') do
    its('content') { should match /^password\s*requisite\s*pam_cracklib\.so.*\n(^password\s*requisite\s*pam_pwhistory\.so\s*(?=.*\bremember=5\b).*$)/ }
  end
end
