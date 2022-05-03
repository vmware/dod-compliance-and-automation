control 'VCRP-70-000001' do
  title 'Envoy must drop connections to disconnected clients.'
  desc  "
    Envoy client connections that are established but no longer connected can consume resources that might otherwise be required by active connections. It is a best practice to terminate connections that are no longer connected to an active client.

    Envoy is hard coded to drop connections after three minutes of idle time. The absence of any \"tcpKeepAliveTimeSec\" settings means that this default is effect. This configuration must be verified and maintained.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # xmllint --xpath '/config/envoy/L4Filter/tcpKeepAliveTimeSec/text()' /etc/vmware-rhttpproxy/config.xml

    Expected result:

    180

    or

    XPath set is empty

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/vmware-rhttpproxy/config.xml

    Locate the <config>/<envoy>/<L4Filter> block and configure <tcpKeepAliveTimeSec> as follows:

    <tcpKeepAliveTimeSec>180</tcpKeepAliveTimeSec>

    Restart the service for changes to take effect.

    # vmon-cli --restart rhttpproxy
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000001-WSR-000001'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCRP-70-000001'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']

  value = input('tcpKeepAliveTimeSec')

  describe.one do
    describe xml("#{input('configXmlPath')}") do
      its(['/config/envoy/L4Filter/tcpKeepAliveTimeSec']) { should cmp value }
    end

    describe xml("#{input('configXmlPath')}") do
      its(['/config/envoy/L4Filter/tcpKeepAliveTimeSec']) { should cmp [] }
    end
  end
end
