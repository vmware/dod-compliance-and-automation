control 'VCEM-70-000013' do
  title 'ESX Agent Manager must have mappings set for Java servlet pages.'
  desc 'Resource mapping is the process of tying a particular file type to a process in the web server that can serve that type of file to a requesting client and identify which file types are not to be delivered to a client.

By not specifying which files can and cannot be served to a user, the web server could deliver to a user web server configuration files, log files, password files, etc.

Because Tomcat is a Java-based web server, the main file extension used is *.jsp. This check ensures the *.jsp file type has been properly mapped to servlets.'
  desc 'check', %q(At the command prompt, run the following command:

# xmllint --format /usr/lib/vmware-eam/web/webapps/eam/WEB-INF/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '/web-app/servlet-mapping/servlet-name[text()="JspServlet"]/parent::servlet-mapping' -

Expected result:

<servlet-mapping>
    <servlet-name>JspServlet</servlet-name>
    <url-pattern>*.jsp</url-pattern>
  </servlet-mapping>

If the output of the command does not match the expected result, this is a finding.)
  desc 'fix', 'Navigate to and open:

/usr/lib/vmware-eam/web/webapps/eam/WEB-INF/web.xml

Navigate to and locate the mapping for the JSP servlet. It is the <servlet-mapping> node that contains <servlet-name>JspServlet</servlet-name>.

Configure the <servlet-mapping> node to look like the code snippet below:

<servlet-mapping>
    <servlet-name>JspServlet</servlet-name>
    <url-pattern>*.jsp</url-pattern>
  </servlet-mapping>

Restart the service with the following command:

# vmon-cli --restart eam'
  impact 0.5
  tag check_id: 'C-60360r888609_chk'
  tag severity: 'medium'
  tag gid: 'V-256685'
  tag rid: 'SV-256685r888611_rule'
  tag stig_id: 'VCEM-70-000013'
  tag gtitle: 'SRG-APP-000141-WSR-000083'
  tag fix_id: 'F-60303r888610_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  list = ['*.jsp', '*.jspx']
  describe xml("#{input('webXmlPath')}") do
    its('/web-app/servlet-mapping[servlet-name="JspServlet"]/url-pattern') { should be_in list }
  end
end
