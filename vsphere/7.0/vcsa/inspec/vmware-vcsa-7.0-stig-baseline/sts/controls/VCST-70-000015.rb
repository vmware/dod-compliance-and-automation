control 'VCST-70-000015' do
  title 'The Security Token Service must be configured with memory leak protection.'
  desc  "
    The Java Runtime environment can cause a memory leak or lock files under certain conditions. Without memory leak protection, the Security Token Service can continue to consume system resources which will lead to \"OutOfMemoryErrors\" when reloading web applications.

    Memory leaks occur when JRE code uses the context class loader to load a singleton. This this will cause a memory leak if a web application class loader happens to be the context class loader at the time. The \"JreMemoryLeakPreventionListener\" class is designed to initialise these singletons when Tomcat's common class loader is the context class loader. Proper use of JRE memory leak protection will ensure that the hosted application does not consume system resources and cause an unstable environment.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # grep JreMemoryLeakPreventionListener /usr/lib/vmware-sso/vmware-sts/conf/server.xml

    Expected result:

    <Listener className=\"org.apache.catalina.core.JreMemoryLeakPreventionListener\"/>

    If the output of the command does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/vmware-sso/vmware-sts/conf/server.xml

    Navigate to the <Server> node.

    Add '<Listener className=\"org.apache.catalina.core.JreMemoryLeakPreventionListener\"/>' to the <Server> node.

    Restart the service with the following command:

    # vmon-cli --restart sts
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-WSR-000086'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCST-70-000015'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe xml("#{input('serverXmlPath')}") do
    its('Server/Listener/attribute::className') { should include "#{input('memLeakListener')}" }
  end
end
