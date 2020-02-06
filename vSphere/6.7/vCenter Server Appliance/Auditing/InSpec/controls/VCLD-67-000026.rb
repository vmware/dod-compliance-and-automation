control "VCLD-67-000026" do
  title "VAMI baseline should be documented and maintained."
  desc  "Making certain that the web server has not been updated by an
unauthorized user is always a concern. Adding patches, functions, and modules
that are untested and not part of the baseline opens the possibility for
security risks. The web server must offer, and not hinder, a method that allows
for the quick and easy reinstallation of a verified and patched baseline to
guarantee the production web server is up-to-date and has not been modified to
add functionality or expose security risks."
  tag component: "vami"
  tag severity: nil
  tag gtitle: "SRG-APP-000225-WSR-000074"
  tag gid: nil
  tag rid: "VCLD-67-000026"
  tag stig_id: "VCLD-67-000026"
  tag fix_id: nil
  tag cci: "CCI-001190"
  tag nist: ["SC-24", "Rev_4"]
  tag false_negatives: nil
  tag false_positives: nil
  tag documentable: nil
  tag mitigations: nil
  tag severity_override_guidance: nil
  tag potential_impacts: nil
  tag third_party_tools: nil
  tag mitigation_controls: nil
  tag responsibility: nil
  tag ia_controls: "SC-24"
  tag check: "Ensure that the VCSA is fully up to date on patches. If anomolous
behavior is detected then the VCSA must be redepolyed or reverted to a known
good snapshot."
  tag fix: "Ensure that the VCSA is fully up to date on patches. If anomolous
behavior is detected then the VCSA must be redepolyed or reverted to a known
good snapshot."
end

