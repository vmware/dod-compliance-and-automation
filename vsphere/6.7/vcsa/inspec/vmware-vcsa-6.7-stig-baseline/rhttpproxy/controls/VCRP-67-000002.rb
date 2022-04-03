control 'VCRP-67-000002' do
  title 'The rhttpproxy must set a limit on established connections.'
  desc  "The rhttpproxy client connections must be limited to preserve system
resources and continue servicing connections without interruption. Without a
limit set, the system would be vulnerable to a trivial denial-of-service attack
where connections are created en masse and vCenter resources are entirely
consumed. The rhttproxy comes configured with a tested and supported value that
must be maintained."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # xmllint --xpath '/config/vmacore/http/maxConnections'
/etc/vmware-rhttpproxy/config.xml

    Expected result:

    <maxConnections> 2048 </maxConnections>

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open /etc/vmware-rhttpproxy/config.xml.

    Locate the <config>/<vmacore>/<http> block and configure <maxConnections>
as follows:

    <maxConnections> 2048 </maxConnections>

    Restart the service for changes to take effect.

    # vmon-cli --restart rhttpproxy
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000001-WSR-000001'
  tag gid: 'V-240717'
  tag rid: 'SV-240717r679664_rule'
  tag stig_id: 'VCRP-67-000002'
  tag fix_id: 'F-43909r679663_fix'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']

  value = input('maxconnections')

  describe.one do
    describe xml("#{input('configXmlPath')}") do
      its(['/config/vmacore/http/maxConnections']) { should cmp [value] }
    end

    describe xml("#{input('configXmlPath')}") do
      its(['/config/vmacore/http/maxConnections']) { should cmp [" #{value} "] }
    end
  end
end
