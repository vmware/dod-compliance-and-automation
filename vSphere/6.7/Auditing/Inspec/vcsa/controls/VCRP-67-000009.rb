control "VCRP-67-000009" do
  title "rhttpproxy log files must be moved to a permanent repository in
accordance with site policy."
  desc  "rhttpproxy produces a handful of logs that must be offloaded from the
originating system. This information can then be used for diagnostic purposes,
forensics purposes, or other purposes relevant to ensuring the availability and
integrity of the hosted application."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-APP-000358-WSR-000063"
  tag gid: nil
  tag rid: "VCRP-67-000009"
  tag stig_id: "VCRP-67-000009"
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

# grep \"<outputToSyslog>\" /etc/vmware-rhttpproxy/config.xml

If the value of 'outputToSyslog' is not set to 'true', is missing or is
commented, this is a finding."
  tag fix: "Navigate to and open /etc/vmware-rhttpproxy/config.xml

Locate the <log> block and configure <outputToSyslog> as follows:

<outputToSyslog>true</outputToSyslog>

Restart the service for changes to take effect.

# vmon-cli --restart rhttpproxy"

  describe xml('/etc/vmware-rhttpproxy/config.xml') do
    its(['/config/log/outputToSyslog']) { should cmp ['true'] }
  end

end