control 'VCUI-67-000012' do
  title 'vSphere UI must have mappings set for Java servlet pages.'
  desc  "Resource mapping is the process of tying a particular file type to a
process in the web server that can serve that type of file to a requesting
client and identify which file types are not to be delivered to a client.

    By not specifying which files can and cannot be served to a user, the web
server could deliver to a user web server configuration files, log files,
password files, etc.

    As Tomcat is a Java-based web server, the main file extension used is
*.jsp. This check ensures that the *.jsp and *.jspx file types has been
properly mapped to servlets.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # xmllint --format /usr/lib/vmware-vsphere-ui/server/conf/web.xml | sed
's/xmlns=\".*\"//g' | xmllint --xpath
'/web-app/servlet-mapping/servlet-name[text()=\"jsp\"]/parent::servlet-mapping'
-

    Expected result:

    <servlet-mapping>
        <servlet-name>jsp</servlet-name>
        <url-pattern>*.jsp</url-pattern>
        <url-pattern>*.jspx</url-pattern>
    </servlet-mapping>

    If the jsp and jspx file url-patterns are not configured as in the expected
result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open /usr/lib/vmware-vsphere-ui/server/conf/web.xml.

    Navigate to and locate the mapping for the JSP servlet. It is the
<servlet-mapping> node that contains <servlet-name>jsp</servlet-name>.

    Configure the <servlet-mapping> node to look like the code snippet below:

        <!-- The mappings for the JSP servlet -->
        <servlet-mapping>
            <servlet-name>jsp</servlet-name>
            <url-pattern>*.jsp</url-pattern>
            <url-pattern>*.jspx</url-pattern>
        </servlet-mapping>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-WSR-000083'
  tag gid: 'V-239693'
  tag rid: 'SV-239693r679185_rule'
  tag stig_id: 'VCUI-67-000012'
  tag fix_id: 'F-42885r679184_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  list = ['*.jsp', '*.jspx']
  describe xml("#{input('webXmlPath')}") do
    its('/web-app/servlet-mapping[servlet-name="jsp"]/url-pattern') { should be_in list }
  end
end
