control 'VCLU-70-000015' do
  title 'Lookup Service must be configured with memory leak protection.'
  desc %q(The Java Runtime environment can cause a memory leak or lock files under certain conditions. Without memory leak protection, Lookup Service can continue to consume system resources, which will lead to "OutOfMemoryErrors" when reloading web applications.

Memory leaks occur when JRE code uses the context class loader to load a singleton as this will cause a memory leak if a web application class loader happens to be the context class loader at the time. The "JreMemoryLeakPreventionListener" class is designed to initialize these singletons when Tomcat's common class loader is the context class loader. Proper use of JRE memory leak protection will ensure that the hosted application does not consume system resources and cause an unstable environment.)
  desc 'check', 'At the command prompt, run the following command:

# grep JreMemoryLeakPreventionListener /usr/lib/vmware-lookupsvc/conf/server.xml

Expected result:

<Listener className="org.apache.catalina.core.JreMemoryLeakPreventionListener"/>

If the output of the command does not match the expected result, this is a finding.'
  desc 'fix', %q(Navigate to and open:

/usr/lib/vmware-lookupsvc/conf/server.xml

Navigate to the <Server> node.

Add '<Listener className="org.apache.catalina.core.JreMemoryLeakPreventionListener"/>' to the <Server> node.

Restart the service with the following command:

# vmon-cli --restart lookupsvc)
  impact 0.5
  tag check_id: 'C-60395r888749_chk'
  tag severity: 'medium'
  tag gid: 'V-256720'
  tag rid: 'SV-256720r888751_rule'
  tag stig_id: 'VCLU-70-000015'
  tag gtitle: 'SRG-APP-000141-WSR-000086'
  tag fix_id: 'F-60338r888750_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe xml("#{input('serverXmlPath')}") do
    its('Server/Listener/attribute::className') { should include "#{input('memLeakListener')}" }
  end
end
