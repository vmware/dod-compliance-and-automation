control 'VRPS-8X-000137' do
  title 'The VMware Aria Operations Casa service directory listings parameter must be disabled.'
  desc  "
    Enumeration techniques, such as URL parameter manipulation, rely on being able to obtain information about the web server's directory structure by locating directories without default pages. In this scenario, the web server will display to the user a listing of the files in the directory being accessed. Ensuring that directory listing is disabled is one approach to mitigating the vulnerability.

    In Tomcat, directory listing is disabled by default but can be enabled via the \"listings\" parameter. Ensure this node is not present to have the default effect.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # xmllint --xpath \"//*[contains(text(), 'DefaultServlet')]/parent::*\" /usr/lib/vmware-casa/casa-webapp/conf/web.xml

    Example result:

    <servlet>
      <servlet-name>default</servlet-name>
      <servlet-class>org.apache.catalina.servlets.DefaultServlet</servlet-class>
        ...
        <init-param>
          <param-name>listings</param-name>
          <param-value>false</param-value>
        </init-param>
        ...
    </servlet>

    If the \"listings\" parameter is specified and is not \"false\", this is a finding.

    If the \"listings\" parameter does not exist, this is not a finding.
  "
  desc 'fix', "
    Navigate to and open the /usr/lib/vmware-casa/casa-webapp/conf/web.xml file.

    Navigate to the /<web-apps>/<servlet>/<servlet-class>org.apache.catalina.servlets.DefaultServlet</servlet-class>/ node and remove the following nodes:

    <init-param>
          <param-name>listings</param-name>
          <param-value>true</param-value>
    </init-param>

    Restart the service with the following command:

    # systemctl restart vmware-casa.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag gid: 'V-VRPS-8X-000137'
  tag rid: 'SV-VRPS-8X-000137'
  tag stig_id: 'VRPS-8X-000137'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  # Open web.xml
  xmlconf = xml(input('casa-webXmlPath'))

  # find the DefaultServlet, if there, then find the 'readOnly' parent node (init-param) and get its param-value (default is 'true' if not present)
  describe xmlconf["//*[contains(text(), 'DefaultServlet')]/parent::*/init-param[param-name = 'listings']/param-value"] do
    it { should be_in ['', 'false'] }
  end
end
