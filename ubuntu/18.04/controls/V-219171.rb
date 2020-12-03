control 'V-219171' do
  title "The Ubuntu operating system must automatically lock an account until the locked
  account is released by an administrator when three unsuccessful logon attempts."
  desc "By limiting the number of failed logon attempts, the risk of
    unauthorized system access via user password guessing, otherwise known as
    brute-forcing, is reduced. Limits are imposed by locking the account.
  "
  impact 0.3
  tag "gtitle": "SRG-OS-000329-GPOS-00128"
  tag "satisfies": nil
  tag "gid": 'V-219171'
  tag "rid": "SV-219171r379606_rule"
  tag "stig_id": "UBTU-18-010039"
  tag "fix_id": "F-20895r304842_fix"
  tag "cci": [ "CCI-002238" ]
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
  desc 'check', "Check that Ubuntu operating system locks an account after three unsuccessful
    login attempts with the following:

    # grep pam_tally2 /etc/pam.d/common-auth

    auth required pam_tally2.so onerr=fail deny=3

    If the command above does not return a pam_tally2.so line with both onerr=fail and deny=3
    parameters, this is a finding.
  "
  desc 'fix', "Configure the Ubuntu operating system to lock an account after three
    unsuccessful login attempts.

    Edit the /etc/pam.d/common-auth file and add the following line:

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
