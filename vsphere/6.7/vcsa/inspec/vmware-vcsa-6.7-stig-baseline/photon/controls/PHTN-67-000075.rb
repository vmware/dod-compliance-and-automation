control 'PHTN-67-000075' do
  title 'The Photon operating system must use the pam_cracklib module.'
  desc  "If the operating system allows the user to select passwords based on
dictionary words, this increases the chances of password compromise by
increasing the opportunity for successful guesses and brute-force attacks."
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # grep pam_cracklib /etc/pam.d/system-password

    If the output does not return at least \"password  requisite
pam_cracklib.so\", this is a finding.
  "
  desc 'fix', "
    Open /etc/applmgmt/appliance/system-password with a text editor.

    Comment out any existing \"pam_cracklib.so\" line and add the following:

    password requisite pam_cracklib.so dcredit=-1 ucredit=-1 lcredit=-1
ocredit=-1 minlen=8 minclass=4 difok=4 retry=3 maxsequence=0 enforce_for_root

    Save and close.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00225'
  tag gid: 'V-239146'
  tag rid: 'SV-239146r816654_rule'
  tag stig_id: 'PHTN-67-000075'
  tag fix_id: 'F-42316r816653_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe file('/etc/pam.d/system-password') do
    its('content') { should match /^(?=.*?\bpassword\b)(?=.*?\brequisite\b)(?=.*?\bpam_cracklib.so\b).*$/ }
  end
end
