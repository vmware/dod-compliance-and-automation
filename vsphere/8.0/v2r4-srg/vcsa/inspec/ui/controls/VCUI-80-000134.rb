control 'VCUI-80-000134' do
  title 'The vCenter UI service shutdown port must be disabled.'
  desc  'Tomcat by default listens on TCP port 8005 to accept shutdown requests. By connecting to this port and sending the SHUTDOWN command, all applications within Tomcat are halted. The shutdown port is not exposed to the network as it is bound to the loopback interface. Setting the port to "-1" in $CATALINA_BASE/conf/server.xml instructs Tomcat to not listen for the shutdown command.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following commands:

    # xmllint --xpath \"//Server/@port\" /usr/lib/vmware-vsphere-ui/server/conf/server.xml
    # grep shutdown.port /etc/vmware/vmware-vmon/svcCfgfiles/vsphere-ui.json

    Example results:

    port=\"${shutdown.port}\"
    \"-Dshutdown.port=-1\",

    If \"port\" does not equal \"${shutdown.port}\", this is a finding.

    If \"shutdown.port\" does not equal \"-1\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/vmware-vsphere-ui/server/conf/catalina.properties

    Add or modify the setting \"shutdown.port=-1\" in the \"catalina.properties\" file.

    Navigate to and open:

    /usr/lib/vmware-vsphere-ui/server/conf/server.xml

    Configure the <Server> node with the value:

    port=\"${shutdown.port}\"

    Restart the service with the following command:

    # vmon-cli --restart vsphere-ui
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag gid: 'V-VCUI-80-000134'
  tag rid: 'SV-VCUI-80-000134'
  tag stig_id: 'VCUI-80-000134'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe json("#{input('svcJsonPath')}") do
    its(['StartCommandArgs']) { should include '-Dshutdown.port=-1' }
  end
  describe xml("#{input('serverXmlPath')}") do
    its(['/Server/@port']) { should cmp '${shutdown.port}' }
  end
end
