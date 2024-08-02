control 'VRPU-8X-000130' do
  title 'The VMware Aria Operations UI service DefaultServlet must be set to "readonly" for "PUT" and "DELETE" commands.'
  desc  "
    The default servlet (or DefaultServlet) is a special servlet provided with Tomcat that is called when no other suitable page is found in a particular folder. The DefaultServlet serves static resources as well as directory listings. The DefaultServlet is configured by default with the \"readonly\" parameter set to \"true\" where HTTP commands such as \"PUT\" and \"DELETE\" are rejected.

    Changing this to \"false\" allows clients to delete or modify static resources on the server and to upload new resources. DefaultServlet \"readonly\" must be set to \"true\", either literally or by absence (default).
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # xmllint --xpath \"//*[contains(text(), 'DefaultServlet')]/parent::*\" /usr/lib/vmware-vcops/tomcat-web-app/conf/web.xml

    Example output:

    <servlet>
      <servlet-name>default</servlet-name>
      <servlet-class>org.apache.catalina.servlets.DefaultServlet</servlet-class>
        ...
        <init-param>
          <param-name>readonly</param-name>
          <param-value>true</param-value>
        </init-param>
        ...
    </servlet>

    If the \"readonly\" param-value for the \"DefaultServlet\" servlet class is set to \"false\", this is a finding.

    If the \"readonly\" param-value does not exist, this is not a finding.
  "
  desc 'fix', "
    Navigate to and open the /usr/lib/vmware-vcops/tomcat-web-app/conf/web.xml file.

    Navigate to the /<web-apps>/<servlet>/<servlet-class>org.apache.catalina.servlets.DefaultServlet</servlet-class>/ node and remove the following nodes:

    <init-param>
          <param-name>readonly</param-name>
          <param-value>false</param-value>
    </init-param>

    Restart the service with the following command:

    # systemctl restart vmware-vcops-web.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000033-AS-000024'
  tag gid: 'V-VRPU-8X-000130'
  tag rid: 'SV-VRPU-8X-000130'
  tag stig_id: 'VRPU-8X-000130'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
  # Open web.xml
  xmlconf = xml(input('ui-webXmlPath'))

  # find the DefaultServlet, if there, then find the 'readOnly' parent node (init-param) and get its param-value (default is 'true' if not present)
  describe xmlconf["//*[contains(text(), 'DefaultServlet')]/parent::*/init-param[param-name = 'readonly']/param-value"] do
    it { should be_in ['', 'true'] }
  end
end
