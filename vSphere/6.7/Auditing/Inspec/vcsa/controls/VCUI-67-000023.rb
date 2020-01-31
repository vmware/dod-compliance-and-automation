control "VCUI-67-000023" do
  title "vSphere UI must be configured to show error pages with minimal
information."
  desc  "Web servers will often display error messages to client users
displaying enough information to aid in the debugging of the error. The
information given back in error messages may display the web server type,
version, patches installed, plug-ins and modules installed, type of code being
used by the hosted application, and any backends being used for data storage.
This information could be used by an attacker to blueprint what type of attacks
might be successful. As such, vSphere UI must be configured to not show server
version information in error pages."
  impact CAT II
  tag severity: "CAT II"
  tag gtitle: nil
  tag gid: nil
  tag rid: "VCUI-67-000023"
  tag stig_id: "VCUI-67-000023"
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

# xmllint --format /usr/lib/vmware-vsphere-ui/server/conf/server.xml | xmllint
--xpath
'/Server/Service/Engine/Host/Valve[@className=\"org.apache.catalina.valves.ErrorReportValve\"]'
-

Expected result:

<Valve className=\"org.apache.catalina.valves.ErrorReportValve\"
showServerInfo=\"false\"/>

If the output of the command does not match the expected result, this is a
finding."
  tag fix: "Navigate to and open
/usr/lib/vmware-vsphere-ui/server/conf/server.xml . Locate the following Host
block:

<Host name=\"localhost\"\" ...>
...
</Host>

Inside this block, add the following on a new line:

<Valve className=\"org.apache.catalina.valves.ErrorReportValve\"
showServerInfo=\"false\"/>"
end

