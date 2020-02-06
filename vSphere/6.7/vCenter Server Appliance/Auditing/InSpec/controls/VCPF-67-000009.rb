control "VCPF-67-000009" do
  title "Performance Charts must only run one webapp."
  desc  "VMware ships Performance Charts on the VCSA with one webapp. Any other
path is potentially malicious and must be removed."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-APP-000131-WSR-000073"
  tag gid: nil
  tag rid: "VCPF-67-000009"
  tag stig_id: "VCPF-67-000009"
  tag fix_id: nil
  tag cci: "CCI-001749"
  tag nist: ["CM-5 (3)", "Rev_4"]
  tag false_negatives: nil
  tag false_positives: nil
  tag documentable: nil
  tag mitigations: nil
  tag severity_override_guidance: nil
  tag potential_impacts: nil
  tag third_party_tools: nil
  tag mitigation_controls: nil
  tag responsibility: nil
  tag ia_controls: "CM-5 (3)"
  tag check: "At the command prompt, execute the following command:

# ls -A /usr/lib/vmware-perfcharts/tc-instance/webapps

Expected result:

statsreport

If the output does not match the expected result, this is a finding."
  tag fix: "For each unexpected directory returned in the check, run the
following command:

# rm /usr/lib/vmware-sso/vmware-sts/webapps/<NAME>

Restart the service with the following command:

# service-control --restart vmware-perfcharts"

  describe command('ls -A /usr/lib/vmware-perfcharts/tc-instance/webapps') do
    its ('stdout.strip') { should eq 'statsreport' }
  end

end