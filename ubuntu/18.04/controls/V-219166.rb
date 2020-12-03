control 'V-219166' do
  title "The Ubuntu operating system must be configured so that three consecutive invalid
    logon attempts by a user locks the account."
  desc  "By limiting the number of failed logon attempts, the risk of
    unauthorized system access via user password guessing, otherwise known as
    brute-forcing, is reduced. Limits are imposed by locking the account.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000021-GPOS-00005"
  tag "satisfies": nil
  tag "gid": 'V-219166'
  tag "rid": "SV-219166r378517_rule"
  tag "stig_id": "UBTU-18-010033"
  tag "fix_id": "F-20890r304827_fix"
  tag "cci": [ "CCI-000044" ]
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
  desc 'check', "Check that Ubuntu operating system locks an account after
    three unsuccessful login attempts with following command:

    # grep pam_tally2 /etc/pam.d/common-auth

    auth required pam_tally2.so onerr=fail deny=3

    If no line is returned or the line is commented out, this is a finding.
    If the line is missing \"onerr=fail\", this is a finding.
    If the line has \"deny\" set to a value more than 3, this is a finding.
  "

  desc 'fix', "Configure the Ubuntu operating system to lock an account after
    three unsuccessful login attempts.

    Edit the /etc/pam.d/common-auth file. The pam_tally2.so entry must be placed at the top of
    the \"auth\" stack. So add the following line before the first \"auth\" entry in the file.

    auth required pam_tally2.so onerr=fail deny=3
  "

  describe file('/etc/pam.d/common-auth') do
    it { should exist }
  end

  describe command('grep pam_tally /etc/pam.d/common-auth') do
    its('exit_status') { should eq 0 }
    its('stdout.strip') { should match /^\s*auth\s+required\s+pam_tally2.so\s+.*onerr=fail\s+deny=3($|\s+.*$)/ }
    its('stdout.strip') { should_not match /^\s*auth\s+required\s+pam_tally2.so\s+.*onerr=fail\s+deny=3\s+.*unlock_time.*$/ }
  end
end
