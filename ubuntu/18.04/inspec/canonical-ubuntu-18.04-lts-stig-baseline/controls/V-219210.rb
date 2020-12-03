control 'V-219210' do
  title 'All passwords must contain at least one special character.'
  desc  "Use of a complex password helps to increase the time and resources
    required to compromise the password. Password complexity or strength is a
    measure of the effectiveness of a password in resisting attempts at guessing
    and brute-force attacks.

    Password complexity is one factor in determining how long it takes to crack
    a password. The more complex the password, the greater the number of possible
    combinations that need to be tested before the password is compromised.

    Special characters are those characters that are not alphanumeric. Examples
    include: ~ ! @ # $ % ^ *.
  "
  impact 0.3
  tag "gtitle": "SRG-OS-000266-GPOS-00101"
  tag "gid": 'V-219210'
  tag "rid": "SV-219210r379249_rule"
  tag "stig_id": "UBTU-18-010145"
  tag "fix_id": "F-20934r304959_fix"
  tag "cci": [ "CCI-001619" ]
  tag "nist": nil
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  desc 'check', "Determine if the field \"ocredit\" is set in the \"/etc/security/pwquality.conf\"
    file with the following command:

    # grep -i \"ocredit\" /etc/security/pwquality.conf
    ocredit=-1

    If the \"ocredit\" parameter is greater than \"-1\", or is commented out, this is a finding.
  "
  desc 'fix', "Configure the Ubuntu operating system to enforce password complexity by
    requiring that at least one special character be used.

    Add or update the following line in the \"/etc/security/pwquality.conf\" file to include
    the \"ocredit=-1\" parameter:

    ocredit=-1
  "
  min_num_special_char = input('min_num_special_char')
  config_file = '/etc/security/pwquality.conf'
  config_file_exists = file(config_file).exist?

  if config_file_exists
    describe parse_config_file(config_file) do
      its('ocredit') { should cmp min_num_special_char }
    end
  else
    describe (config_file + ' exists') do
      subject { config_file_exists }
      it { should be true }
    end
  end
end
