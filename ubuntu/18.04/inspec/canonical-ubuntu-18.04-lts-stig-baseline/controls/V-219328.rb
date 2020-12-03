control 'V-219328' do
  title "The Ubuntu operating system default filesystem permissions must be defined in
    such a way that all authenticated users can only read and modify their own files."
  desc  "Setting the most restrictive default permissions ensures that when new
    accounts are created they do not have unnecessary access."
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00228"
  tag "gid": 'V-219328'
  tag "rid": "SV-219328r388482_rule"
  tag "stig_id": "UBTU-18-010448"
  tag "fix_id": "F-21052r305313_fix"
  tag "cci": [ "CCI-000366" ]
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
  desc 'check', "Verify the Ubuntu operating system defines default permissions for all
    authenticated users in such a way that the user can only read and modify their own files.

    Check that the Ubuntu operating system defines default permissions for all authenticated
    users with the following command:

    # grep -i \"umask\" /etc/login.defs

    UMASK 077

    If the \"UMASK\" variable is set to \"000\", this is a finding with the severity raised to a CAT I.

    If the value of \"UMASK\" is not set to \"077\", \"UMASK\" is commented out or \"UMASK\" is
    missing completely, this is a finding.
  "
  desc 'fix', "Configure the system to define the default permissions for all authenticated users
  in such a way that the user can only read and modify their own files.

    Edit the \"UMASK\" parameter in the \"/etc/login.defs\" file to match the example below:

    UMASK 077
  "
  describe login_defs do
    its('UMASK') { should eq '077' }
  end
end
