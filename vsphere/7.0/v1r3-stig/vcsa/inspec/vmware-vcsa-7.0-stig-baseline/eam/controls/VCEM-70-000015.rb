control 'VCEM-70-000015' do
  title 'ESX Agent Manager must be configured with memory leak protection.'
  desc %q(The Java Runtime environment can cause a memory leak or lock files under certain conditions. Without memory leak protection, ESX Agent Manager can continue to consume system resources, which will lead to "OutOfMemoryErrors" when reloading web applications.

Memory leaks occur when JRE code uses the context class loader to load a singleton, as this will cause a memory leak if a web application class loader happens to be the context class loader at the time. The "JreMemoryLeakPreventionListener" class is designed to initialize these singletons when Tomcat's common class loader is the context class loader. Proper use of JRE memory leak protection will ensure the hosted application does not consume system resources and cause an unstable environment.)
  desc 'check', 'At the command prompt, run the following command:

# grep JreMemoryLeakPreventionListener /usr/lib/vmware-eam/web/conf/server.xml

Expected result:

<Listener className="org.apache.catalina.core.JreMemoryLeakPreventionListener"/>

If the output of the command does not match the expected result, this is a finding.'
  desc 'fix', %q(Navigate to and open:

/usr/lib/vmware-eam/web/conf/server.xml

Navigate to the <Server> node.

Add '<Listener className="org.apache.catalina.core.JreMemoryLeakPreventionListener"/>' to the <Server> node.

Restart the service with the following command:

# vmon-cli --restart eam)
  impact 0.5
  tag check_id: 'C-60362r888615_chk'
  tag severity: 'medium'
  tag gid: 'V-256687'
  tag rid: 'SV-256687r888617_rule'
  tag stig_id: 'VCEM-70-000015'
  tag gtitle: 'SRG-APP-000141-WSR-000086'
  tag fix_id: 'F-60305r888616_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe xml("#{input('serverXmlPath')}") do
    its('Server/Listener/attribute::className') { should include "#{input('memLeakListener')}" }
  end
end
