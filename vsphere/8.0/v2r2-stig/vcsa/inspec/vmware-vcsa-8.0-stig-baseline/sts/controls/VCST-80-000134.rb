control 'VCST-80-000134' do
  title 'The vCenter STS service shutdown port must be disabled.'
  desc 'Tomcat by default listens on TCP port 8005 to accept shutdown requests. By connecting to this port and sending the SHUTDOWN command, all applications within Tomcat are halted. The shutdown port is not exposed to the network as it is bound to the loopback interface. Setting the port to "-1" in $CATALINA_BASE/conf/server.xml instructs Tomcat to not listen for the shutdown command.'
  desc 'check', %q(At the command prompt, run the following commands:

# xmllint --xpath "//Server/@port" /usr/lib/vmware-sso/vmware-sts/conf/server.xml
# grep 'base.shutdown.port' /usr/lib/vmware-sso/vmware-sts/conf/catalina.properties

Example results:

port="${base.shutdown.port}"
base.shutdown.port=-1

If "port" does not equal "${base.shutdown.port}", this is a finding.

If "base.shutdown.port" does not equal "-1", this is a finding.)
  desc 'fix', 'Navigate to and open:

/usr/lib/vmware-sso/vmware-sts/conf/catalina.properties

Add or modify the setting "base.shutdown.port=-1" in the "catalina.properties" file.

Navigate to and open:

/usr/lib/vmware-sso/vmware-sts/conf/server.xml

Configure the <Server> node with the value:

port="${base.shutdown.port}"

Restart the service with the following command:

# vmon-cli --restart sts'
  impact 0.5
  tag check_id: 'C-62730r934626_chk'
  tag severity: 'medium'
  tag gid: 'V-258990'
  tag rid: 'SV-258990r960963_rule'
  tag stig_id: 'VCST-80-000134'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag fix_id: 'F-62639r934627_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe parse_config_file("#{input('catalinaPropertiesPath')}").params['base.shutdown.port'] do
    it { should cmp '-1' }
  end
  describe xml("#{input('serverXmlPath')}") do
    its(['/Server/@port']) { should cmp '${base.shutdown.port}' }
  end
end
