control "VCRP-67-000006" do
  title "rhttpproxy must have logging enabled."
  desc  "After a security incident has occurred, investigators will often
review log files to determine what happened. rhttpproxy must create logs upon
service start up in order to capture information relevant to investigations."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-APP-000093-WSR-000053"
  tag gid: nil
  tag rid: "VCRP-67-000006"
  tag stig_id: "VCRP-67-000006"
  tag fix_id: nil
  tag cci: "CCI-001462"
  tag nist: ["AU-14 (2)", "Rev_4"]
  tag false_negatives: nil
  tag false_positives: nil
  tag documentable: nil
  tag mitigations: nil
  tag severity_override_guidance: nil
  tag potential_impacts: nil
  tag third_party_tools: nil
  tag mitigation_controls: nil
  tag responsibility: nil
  tag ia_controls: "AU-14 (2)"
  tag check: "At the command prompt, execute the following command:

# grep \"<outputToFiles>\" /etc/vmware-rhttpproxy/config.xml

If the value of 'outputToFiles' is not set to 'true', is missing or is
commented, this is a finding."
  tag fix: "Navigate to and open /etc/vmware-rhttpproxy/config.xml

Locate the <log> block and configure <outputToFiles> as follows:

<outputToFiles>true</outputToFiles>

Restart the service for changes to take effect.

# vmon-cli --restart rhttpproxy"

  describe xml('/etc/vmware-rhttpproxy/config.xml') do
    its(['/config/log/outputToFiles']) { should cmp ['true'] }
  end

end