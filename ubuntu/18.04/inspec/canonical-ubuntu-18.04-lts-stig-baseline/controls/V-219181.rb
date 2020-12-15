# encoding: UTF-8

control 'V-219181' do
  title "The Ubuntu operating system must enforce a minimum 15-character
password length."
  desc  "The shorter the password, the lower the number of possible
combinations that need to be tested before the password is compromised.

    Password complexity, or strength, is a measure of the effectiveness of a
password in resisting attempts at guessing and brute-force attacks. Password
length is one factor of several that helps to determine strength and how long
it takes to crack a password. Use of more characters in a password helps to
exponentially increase the time and/or resources required to compromise the
password.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify if the pwquality configuration file enforces a minimum 15-character
password length, by running the following command:

    # grep -i minlen /etc/security/pwquality.conf
     minlen=15

    If \"minlen\" parameter value is not 15 or higher, or is commented out,
this is a finding.
  "
  desc  'fix', "
    Configure the Ubuntu operating system to enforce a minimum 15-character
password length.

    Add, or modify the \"minlen\" parameter value to the
\"/etc/security/pwquality.conf\" file:

    minlen=15
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000078-GPOS-00046'
  tag gid: 'V-219181'
  tag rid: 'SV-219181r508662_rule'
  tag stig_id: 'UBTU-18-010109'
  tag fix_id: 'F-20905r304872_fix'
  tag cci: ['SV-109693', 'V-100589', 'CCI-000205']
  tag nist: ['IA-5 (1) (a)']

  config_file = '/etc/security/pwquality.conf'
  config_file_exists = file(config_file).exist?

  if config_file_exists
    describe parse_config_file(config_file) do
      its('minlen') { should cmp >= '15' }
    end
  else
    describe (config_file + ' exists') do
      subject { config_file_exists }
      it { should be true }
    end
  end
end

