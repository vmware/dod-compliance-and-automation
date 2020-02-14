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
  tag cci: "CCI-000054"
  tag nist: ["AC-10", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

# xmllint --xpath '/config/vmacore/tcpKeepAlive/clientSocket/idleTimeSec'
/etc/vmware-rhttpproxy/config.xml

Expected result:

<idleTimeSec>900</idleTimeSec>

If the output does not match the expected result, this is a finding."
  desc 'fix', "Navigate to and open /etc/vmware-rhttpproxy/config.xml

Locate the <clientSocket> block and configure <idleTimeSec> as follows:

<idleTimeSec>900</idleTimeSec>

Restart the service for changes to take effect.

# vmon-cli --restart rhttpproxy"

  describe xml('/etc/vmware-rhttpproxy/config.xml') do
    its(['/config/vmacore/tcpKeepAlive/clientSocket/idleTimeSec']) { should cmp '900' }
  end

end

