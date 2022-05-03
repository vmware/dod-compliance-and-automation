control 'VCRP-70-000002' do
  title 'Envoy must set a limit on established connections.'
  desc  "
    Envoy client connections must be limited in order to preserve system resources and to continue servicing connections without interruption. Without a limit, set the system would be vulnerable to a trivial denial of service attack where connections are created en masse and vCenter resources are entirely consumed.

    Envoy comes hard coded with a tested and supported value for \"maxHttpsConnections\" that must be verified and maintained.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # xmllint --xpath '/config/envoy/L4Filter/maxHttpsConnections/text()' /etc/vmware-rhttpproxy/config.xml

    Expected result:

    2048

    or

    XPath set is empty

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/vmware-rhttpproxy/config.xml

    Locate the <config>/<envoy>/<L4Filter> block and configure <maxHttpsConnections> as follows:

    <maxHttpsConnections>2048</maxHttpsConnections>

    Restart the service for changes to take effect.

    # vmon-cli --restart rhttpproxy
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000001-WSR-000001'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCRP-70-000002'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']

  value = input('maxHttpsConnections')

  describe.one do
    describe xml("#{input('configXmlPath')}") do
      its(['/config/envoy/L4Filter/maxHttpsConnections']) { should cmp value }
    end

    describe xml("#{input('configXmlPath')}") do
      its(['/config/envoy/L4Filter/maxHttpsConnections']) { should cmp [] }
    end
  end
end
