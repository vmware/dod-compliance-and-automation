control "VCRP-67-000001" do
  title "rhttpproxy must drop connections to disconnected clients."
  desc  "rhttpproxy client connections that are established but no longer
connected can consume resources that might otherwise be required by active
connections. It is a best practice to terminate connections that are no longer
connected to an active client."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-APP-000001-WSR-000001"
  tag gid: nil
  tag rid: "VCRP-67-000001"
  tag stig_id: "VCRP-67-000001"
  tag fix_id: nil
  tag cci: "CCI-000054"
  tag nist: ["AC-10", "Rev_4"]
  tag false_negatives: nil
  tag false_positives: nil
  tag documentable: nil
  tag mitigations: nil
  tag severity_override_guidance: nil
  tag potential_impacts: nil
  tag third_party_tools: nil
  tag mitigation_controls: nil
  tag responsibility: nil
  tag ia_controls: "AC-10"
  tag check: "At the command prompt, execute the following command:

# sed -n \"/<clientSocket/,/clientSocket>/p\"
/etc/vmware-rhttpproxy/config.xml|grep -z --color=always 'idleTimeSec'

If the value of 'idleTimeSec' is not set to '900'. is missing or is commented,
this is a finding."
  tag fix: "Navigate to and open /etc/vmware-rhttpproxy/config.xml

Locate the <clientSocket> block and configure <idleTimeSec> as follows:

<idleTimeSec>900</idleTimeSec>

Restart the service for changes to take effect.

# vmon-cli --restart rhttpproxy"

  describe xml('/etc/vmware-rhttpproxy/config.xml') do
    its(['/config/vmacore/tcpKeepAlive/clientSocket/idleTimeSec']) { should cmp '900' }
  end

end