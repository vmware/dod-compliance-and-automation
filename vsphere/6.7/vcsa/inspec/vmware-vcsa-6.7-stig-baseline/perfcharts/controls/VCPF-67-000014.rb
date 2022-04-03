control 'VCPF-67-000014' do
  title 'Performance Charts must be configured with memory leak protection.'
  desc  "The Java Runtime environment can cause a memory leak or lock files
under certain conditions. Without memory leak protection, Performance Chart can
continue to consume system resources that will lead to \"OutOfMemoryErrors\"
when reloading web applications.

    Memory leaks occur when JRE code uses the context class loader to load a
singleton. This will cause a memory leak if a web application class loader
happens to be the context class loader at the time. The
\"JreMemoryLeakPreventionListener\" class is designed to initialize these
singletons when Tomcat's common class loader is the context class loader.
Proper use of JRE memory leak protection will ensure that the hosted
application does not consume system resources and cause an unstable environment.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # grep JreMemoryLeakPreventionListener
/usr/lib/vmware-perfcharts/tc-instance/conf/server.xml

    Expected result:

    <Listener
className=\"org.apache.catalina.core.JreMemoryLeakPreventionListener\"/>

    If the output of the command does not match the expected result, this is a
finding.
  "
  desc 'fix', "
    Navigate to and open /usr/lib/vmware-perfcharts/tc-instance/conf/server.xml.

    Navigate to the <Server> node.

    Add '<Listener
className=\"org.apache.catalina.core.JreMemoryLeakPreventionListener\"/>' to
the <Server> node.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-WSR-000086'
  tag gid: 'V-239415'
  tag rid: 'SV-239415r674968_rule'
  tag stig_id: 'VCPF-67-000014'
  tag fix_id: 'F-42607r674967_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe xml("#{input('serverXmlPath')}") do
    its('Server/Listener/attribute::className') { should include "#{input('memLeakListener')}" }
  end
end
