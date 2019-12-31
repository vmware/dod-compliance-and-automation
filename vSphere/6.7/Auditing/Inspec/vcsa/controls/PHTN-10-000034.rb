control "PHTN-10-000034" do
  title "The Photon operating system must not have Duplicate User IDs (UIDs)."
  desc  "To assure accountability and prevent unauthenticated access,
organizational users must be uniquely identified and authenticated to prevent
potential misuse and provide for non-repudiation."
  tag severity: nil
  tag gtitle: "SRG-OS-000104-GPOS-00051"
  tag gid: nil
  tag rid: "PHTN-10-000034"
  tag stig_id: "PHTN-10-000034"
  tag fix_id: nil
  tag cci: "CCI-000764"
  tag nist: ["IA-2", "Rev_4"]
  tag false_negatives: nil
  tag false_positives: nil
  tag documentable: nil
  tag mitigations: nil
  tag severity_override_guidance: nil
  tag potential_impacts: nil
  tag third_party_tools: nil
  tag mitigation_controls: nil
  tag responsibility: nil
  tag ia_controls: "IA-2"
  tag check: "At the command line, execute the following command:

# awk -F \":\" 'list[$3]++{print $1, $3}' /etc/passwd

If any lines are returned, this is a finding."
  tag fix: "Open /etc/passwd with a text editor.  Configure each user account
that has a duplicate UID with a unique UID."

  describe command('awk -F ":" \'list[$3]++{print $1, $3}\' /etc/passwd') do
      its ('stdout') { should eq '' }
  end

end

