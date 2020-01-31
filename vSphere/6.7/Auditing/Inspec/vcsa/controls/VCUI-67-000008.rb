control "VCUI-67-000008" do
  title "vSphere UI application files must be verified for their integrity."
  desc  "Verifying that the vSphere UI application code is unchanged from it's
shipping state is essential for file validation and non-repudiation of the
vSphere UI itself. There is no reason that the MD5 hash of the rpm original
files should be changed after installation, excluding configuration files."
  impact CAT II
  tag severity: "CAT II"
  tag gtitle: "SRG-APP-000358-WSR-000163"
  tag gid: nil
  tag rid: "VCUI-67-000008"
  tag stig_id: "VCUI-67-000008"
  tag fix_id: nil
  tag cci: "CCI-001851"
  tag nist: ["AU-4 (1)", "Rev_4"]
  tag false_negatives: nil
  tag false_positives: nil
  tag documentable: nil
  tag mitigations: nil
  tag severity_override_guidance: nil
  tag potential_impacts: nil
  tag third_party_tools: nil
  tag mitigation_controls: nil
  tag responsibility: nil
  tag ia_controls: "AU-4 (1)"
  tag check: "At the command prompt, execute the following command:

# rpm -V vsphere-ui|grep \"^..5......\"|grep -E \"\\.war|\\.jar|\\.sh|\\.py\"

If is any output, this is a finding."
  tag fix: "Re-install the VCSA or roll back to a snapshot. Modifying the
vSphere UI installation files manually is not supported by VMware."
end

