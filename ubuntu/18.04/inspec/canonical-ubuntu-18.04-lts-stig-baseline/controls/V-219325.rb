control 'V-219325' do
  title 'Duplicate User IDs (UIDs) must not exist for interactive users.'
  desc  "To assure accountability and prevent unauthenticated access,
    interactive users must be identified and authenticated to prevent potential
    misuse and compromise of the system.

    Interactive users include organizational employees or individuals the
organization deems to have equivalent status of employees (e.g., contractors).
    Interactive users (and processes acting on behalf of users) must be uniquely
    identified and authenticated to all accesses, except for the following:

    1) Accesses explicitly identified and documented by the organization.
Organizations document specific user actions that can be performed on the
    information system without identification or authentication; and

    2) Accesses that occur through authorized use of group authenticators
    without individual authentication. Organizations may require unique
    identification of individuals in group accounts (e.g., shared privilege
    accounts) or for detailed accountability of individual activity.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000104-GPOS-00051"
  tag "satisfies": nil
  tag "gid": 'V-219325'
  tag "rid": "SV-219325r378847_rule"
  tag "stig_id": "UBTU-18-010444"
  tag "fix_id": "F-21049r305304_fix"
  tag "cci": [ "CCI-000764","CCI-000804" ]
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
  desc 'check', "Verify that the Ubuntu operating system contains no duplicate User
    IDs (UIDs) for interactive users.

    Check that the Ubuntu operating system contains no duplicate UIDs for interactive users
    with the following command:

    # awk -F \":\" 'list[$3]++{print $1, $3}' /etc/passwd

    If output is produced, and the accounts listed are interactive user accounts, this is a finding.
  "
  desc 'fix', "Edit the file \"/etc/passwd\" and provide each interactive user account that
    has a duplicate User ID (UID) with a unique UID.
  "
  user_list = command("awk -F \":\" 'list[$3]++{print $1}' /etc/passwd").stdout.split("\n")
  findings = Set[]

  user_list.each do |user_name|
    findings = findings << user_name
  end
  describe 'Duplicate User IDs (UIDs) must not exist for interactive users' do
    subject { findings.to_a }
    it { should be_empty }
  end
end
