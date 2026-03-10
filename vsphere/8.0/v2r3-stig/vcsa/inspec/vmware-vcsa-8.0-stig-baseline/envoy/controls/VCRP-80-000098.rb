control 'VCRP-80-000098' do
  title 'The vCenter Envoy service must set a limit on remote connections.'
  desc 'Envoy client connections must be limited to preserve system resources and continue servicing connections without interruption. Without a limit set, the system would be vulnerable to a trivial denial-of-service attack where connections are created en masse and vCenter resources are entirely consumed.

Envoy comes hard coded with a tested and supported value for "maxRemoteHttpsConnections" and "maxRemoteHttpConnections" that must be verified and maintained.'
  desc 'check', %q(At the command prompt, run the following commands:

# xmllint --xpath '/config/envoy/L4Filter/maxRemoteHttpsConnections/text()' /etc/vmware-rhttpproxy/config.xml
# xmllint --xpath '/config/envoy/L4Filter/maxRemoteHttpConnections/text()' /etc/vmware-rhttpproxy/config.xml

Example result:

2048

or

XPath set is empty

If the output is not "2048" or "XPath set it empty", this is a finding.

Note: If "XPath set is empty" is returned the default values are in effect and is 2048.)
  desc 'fix', 'Navigate to and open:

/etc/vmware-rhttpproxy/config.xml

Locate the <config>/<envoy>/<L4Filter> block and configure it as follows:

<maxRemoteHttpsConnections>2048</maxRemoteHttpsConnections>
<maxRemoteHttpConnections>2048</maxRemoteHttpConnections>

Restart the service for changes to take effect.

# vmon-cli --restart rhttpproxy'
  impact 0.5
  tag check_id: 'C-62905r935397_chk'
  tag severity: 'medium'
  tag gid: 'V-259165'
  tag rid: 'SV-259165r960735_rule'
  tag stig_id: 'VCRP-80-000098'
  tag gtitle: 'SRG-APP-000001-WSR-000001'
  tag fix_id: 'F-62814r935398_fix'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']

  describe.one do
    describe xml("#{input('configXmlPath')}") do
      its(['/config/envoy/L4Filter/maxRemoteHttpsConnections']) { should cmp '2048' }
    end

    describe xml("#{input('configXmlPath')}") do
      its(['/config/envoy/L4Filter/maxRemoteHttpsConnections']) { should cmp [] }
    end
  end
  describe.one do
    describe xml("#{input('configXmlPath')}") do
      its(['/config/envoy/L4Filter/maxRemoteHttpConnections']) { should cmp '2048' }
    end

    describe xml("#{input('configXmlPath')}") do
      its(['/config/envoy/L4Filter/maxRemoteHttpConnections']) { should cmp [] }
    end
  end
end
