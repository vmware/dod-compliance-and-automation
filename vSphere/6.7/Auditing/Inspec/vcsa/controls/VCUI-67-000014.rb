control "VCUI-67-000014" do
  title "vSphere UI must be configured with memory leak protection."
  desc  "The Java Runtime environment can cause a memory leak or lock files
under certain conditions. Without memory leak protection, vSphere UI can
continue to consume system resources which will lead to OutOfMemoryErrors when
re-loading web applications.

    Memory leaks occur when JRE code uses the context class loader to load a
singleton as this will cause a memory leak if a web application class loader
happens to be the context class loader at the time. The
JreMemoryLeakPreventionListener class is designed to initialise these
singletons when Tomcat's common class loader is the context class loader.
Proper use of JRE memory leak protection will ensure that the hosted
application does not consume system resources and cause an unstable environment.
  "
  impact CAT II
  tag severity: "CAT II"
  tag gtitle: nil
  tag gid: nil
  tag rid: "VCUI-67-000014"
  tag stig_id: "VCUI-67-000014"
  tag fix_id: nil
  tag cci: nil
  tag nist: nil
  tag false_negatives: nil
  tag false_positives: nil
  tag documentable: nil
  tag mitigations: nil
  tag severity_override_guidance: nil
  tag potential_impacts: nil
  tag third_party_tools: nil
  tag mitigation_controls: nil
  tag responsibility: nil
  tag ia_controls: nil
  tag check: "At the command prompt, execute the following command:

# grep JreMemoryLeakPreventionListener
/usr/lib/vmware-vsphere-ui/server/conf/server.xml

Expected result:



<Listener
className=\"org.apache.catalina.core.JreMemoryLeakPreventionListener\"/>



If the output of the command does not match the expected result, this is a
finding.

"
  tag fix: "Navigate to and open
/usr/lib/vmware-vsphere-ui/server/conf/server.xml

Navigate to the <Server> node.

Add '<Listener
className=\"org.apache.catalina.core.JreMemoryLeakPreventionListener\"/>' to
the <Server> node."
end

