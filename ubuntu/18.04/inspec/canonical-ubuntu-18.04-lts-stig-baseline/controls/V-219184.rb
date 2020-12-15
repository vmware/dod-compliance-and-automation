# encoding: UTF-8

control 'V-219184' do
  title "The Ubuntu operating system must prevent the use of dictionary words
for passwords."
  desc  "If the Ubuntu operating system allows the user to select passwords
based on dictionary words, then this increases the chances of password
compromise by increasing the opportunity for successful guesses and brute-force
attacks."
  desc  'rationale', ''
  desc  'check', "
    Verify that the Ubuntu operating system uses the cracklib library to
prevent the use of dictionary words with the following command:

    # grep dictcheck /etc/security/pwquality.conf

    dictcheck=1

    If the \"dictcheck\" parameter is not set to \"1\", or is commented out,
this is a finding.
  "
  desc  'fix', "
    Configure the Ubuntu operating system to prevent the use of dictionary
words for passwords.

    Add or update the following line in the \"/etc/security/pwquality.conf\"
file to include the \"dictcheck=1\" parameter:

    dictcheck=1
  "
  
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00225'
  tag gid: 'V-219184'
  tag rid: 'SV-219184r508662_rule'
  tag stig_id: 'UBTU-18-010113'
  tag fix_id: 'F-20908r304881_fix'
  tag cci: ['SV-109699', 'V-100595', 'CCI-000366']
  tag nist: ['CM-6 b']

  config_file = '/etc/security/pwquality.conf'
  config_file_exists = file(config_file).exist?

  if config_file_exists
    describe parse_config_file(config_file) do
      its('dictcheck') { should cmp '1' }
    end
  else
    describe (config_file + ' exists') do
      subject { config_file_exists }
      it { should be true }
    end
  end
end

