control "VCUI-67-000012" do
  title "vSphere UI must have mappings set for Java servlet pages."
  desc  "Resource mapping is the process of tying a particular file type to a
process in the web server that can serve that type of file to a requesting
client and to identify which file types are not to be delivered to a client.

    By not specifying which files can and which files cannot be served to a
user, the web server could deliver to a user web server configuration files,
log files, password files, etc.

    As Tomcat is a java-based web server, the main file extension used is
*.jsp.  This check ensures that the *.jsp and *.jspx file types has been
properly mapped to servlets.
  "
  impact CAT II
  tag severity: "CAT II"
  tag gtitle: "SRG-APP-000456-WSR-000187"
  tag gid: nil
  tag rid: "VCUI-67-000012"
  tag stig_id: "VCUI-67-000012"
  tag fix_id: nil
  tag cci: "CCI-002605"
  tag nist: ["SI-2 c", "Rev_4"]
  tag false_negatives: nil
  tag false_positives: nil
  tag documentable: nil
  tag mitigations: nil
  tag severity_override_guidance: nil
  tag potential_impacts: nil
  tag third_party_tools: nil
  tag mitigation_controls: nil
  tag responsibility: nil
  tag ia_controls: "SI-2 c"
  tag check: "At the command prompt, execute the following command:

# xmllint --format /usr/lib/vmware-vsphere-ui/server/conf/web.xml | sed
's/xmlns=\".*\"//g' | xmllint --xpath
'/web-app/servlet-mapping/servlet-name[text()=\"jsp\"]/parent::servlet-mapping'
-

Expected result:

<servlet-mapping>
 \xC2\xA0 \xC2\xA0<servlet-name>jsp</servlet-name>
 \xC2\xA0 \xC2\xA0<url-pattern>*.jsp</url-pattern>
 \xC2\xA0 \xC2\xA0<url-pattern>*.jspx</url-pattern>
</servlet-mapping>

If the jsp and jspx file url-patterns are not configured as in the expected
result, this is a finding."
  tag fix: "Navigate to and open /usr/lib/vmware-vsphere-ui/server/conf/web.xml

Navigate to and locate the mapping for the JSP servlet. \xC2\xA0It is the
\xC2\xA0<servlet-mapping> node that contains <servlet-name>jsp</servlet-name>

Configure the <servlet-mapping> node to look like the code snippet below

 \xC2\xA0 \xC2\xA0<!-- The mappings for the JSP servlet -->
 \xC2\xA0 \xC2\xA0<servlet-mapping>
 \xC2\xA0 \xC2\xA0 \xC2\xA0 \xC2\xA0<servlet-name>jsp</servlet-name>
 \xC2\xA0 \xC2\xA0 \xC2\xA0 \xC2\xA0<url-pattern>*.jsp</url-pattern>
 \xC2\xA0 \xC2\xA0 \xC2\xA0 \xC2\xA0<url-pattern>*.jspx</url-pattern>
 \xC2\xA0 \xC2\xA0</servlet-mapping>
"
end

