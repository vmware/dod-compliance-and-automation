control 'VRPS-8X-000134' do
  title 'The Casa service shutdown port must be disabled.'
  desc  'Tomcat by default listens on TCP port 8005 to accept shutdown requests. By connecting to this port and sending the SHUTDOWN command, all applications within Tomcat are halted. The shutdown port is not exposed to the network as it is bound to the loopback interface. Setting the port to "-1" in $CATALINA_BASE/conf/server.xml instructs Tomcat to not listen for the shutdown command.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following commands:

    # xmllint --xpath \"//Server/@port\" $CATALINA_BASE/conf/server.xml
    # grep 'base.shutdown.port' $CATALINA_BASE/conf/catalina.properties

    Expected results:

    port=\"${base.shutdown.port}\"
    base.shutdown.port=-1

    If \"port\" does not equal \"${base.shutdown.port}\", this is a finding.

    If \"base.shutdown.port\" does not equal \"-1\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    $CATALINA_BASE/conf/catalina.properties

    Add or modify the setting \"base.shutdown.port=-1\" in the \"catalina.properties\" file.

    Navigate to and open:

    $CATALINA_BASE/conf/server.xml

    Configure the <Server> node with the value:

    port=\"${base.shutdown.port}\"

    Restart the service with the following command:

    # systemctl restart vmware-casa.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag gid: 'V-VRPS-8X-000134'
  tag rid: 'SV-VRPS-8X-000134'
  tag stig_id: 'VRPS-8X-000134'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
  describe parse_config_file("#{input('casa-catalinaPropsPath')}").params['base.shutdown.port'] do
    it { should cmp '-1' }
  end
  describe xml("#{input('casa-serverXmlPath')}") do
    its(['/Server/@port']) { should cmp '${base.shutdown.port}' }
  end
end
