control 'V-219180' do
  title "The Ubuntu operating system must prohibit password reuse for a minimum of five
    generations."
  desc  "Password complexity, or strength, is a measure of the effectiveness of
    a password in resisting attempts at guessing and brute-force attacks. If the
    information system or application allows the user to consecutively reuse their
    password when that password has exceeded its defined lifetime, the end result
    is a password that is not changed as per policy requirements.
  "
  impact 0.3
  tag "gtitle": "SRG-OS-000077-GPOS-00045"
  tag "gid": 'V-219180'
  tag "rid": "SV-219180r378763_rule"
  tag "stig_id": "UBTU-18-010108"
  tag "fix_id": "F-20904r304869_fix"
  tag "cci": [ "CCI-000200" ]
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
  desc 'check', "Verify that the Ubuntu operating system prevents passwords from being
    reused for a minimum of five generations by running the following command:

    # grep -i remember /etc/pam.d/common-password

    password [success=1 default=ignore] pam_unix.so sha512 shadow remember=5 rounds=5000

    If the \"remember\" parameter value is not greater than or equal to 5, commented out,
    or not set at all this is a finding.
  "

  desc 'fix', "Configure the Ubuntu operating system prevents passwords from being reused
    for a minimum of five generations.

    Add, or modify the \"remember\" parameter value to the following line in
    \"/etc/pam.d/common-password\" file:

    password [success=1 default=ignore] pam_unix.so sha512 shadow remember=5 rounds=5000
  "

  min_num_password_generations = input('min_num_password_generations')

  describe file('/etc/pam.d/common-password') do
    it { should exist }
  end

  describe command("grep -i remember /etc/pam.d/common-password | sed 's/.*remember=\\([^ ]*\\).*/\\1/'") do
    its('exit_status') { should eq 0 }
    its('stdout.strip') { should cmp min_num_password_generations }
  end
end
