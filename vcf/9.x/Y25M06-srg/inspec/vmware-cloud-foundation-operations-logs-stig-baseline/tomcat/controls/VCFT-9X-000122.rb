control 'VCFT-9X-000122' do
  title 'The VMware Cloud Foundation Operations for Logs Loginsight service DefaultServlet must be set to "readonly" for "PUT" and "DELETE" commands.'
  desc  "
    The default servlet (or DefaultServlet) is a special servlet provided with Tomcat that is called when no other suitable page is found in a particular folder. The DefaultServlet serves static resources as well as directory listings. The DefaultServlet is configured by default with the \"readonly\" parameter set to \"true\" where HTTP commands such as \"PUT\" and \"DELETE\" are rejected.

    Changing this to \"false\" allows clients to delete or modify static resources on the server and to upload new resources. DefaultServlet \"readonly\" must be set to \"true\", either literally or by absence (default).
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following:

    # xmllint --xpath \"//*[contains(text(), 'DefaultServlet')]/parent::*\" /usr/lib/loginsight/application/3rd_party/apache-tomcat/conf/web.xml

    Example output:

    <servlet>
    \t<servlet-name>default</servlet-name>
    \t<servlet-class>org.apache.catalina.servlets.DefaultServlet</servlet-class>
    \t<init-param>
    \t\t<param-name>debug</param-name>
    \t\t<param-value>0</param-value>
    \t</init-param>
    \t<init-param>
    \t\t<param-name>listings</param-name>
    \t\t<param-value>false</param-value>
    \t</init-param>
    \t<init-param>
    \t\t<param-name>readOnly</param-name>
    \t\t<param-value>true</param-value>
    \t</init-param>
    \t<load-on-startup>1</load-on-startup>
    </servlet>

    If the \"readOnly\" param-value for the \"DefaultServlet\" servlet class is set to \"false\", this is a finding.

    If the \"readOnly\" param-value does not exist, this is not a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/loginsight/application/3rd_party/apache-tomcat/conf/web.xml

    Navigate to the /<web-apps>/<servlet>/<servlet-class>org.apache.catalina.servlets.DefaultServlet</servlet-class>/ node and remove the following node:

    <init-param>
          <param-name>readonly</param-name>
          <param-value>false</param-value>
    </init-param>

    Restart the service with the following command:

    # systemctl restart loginsight.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: 'V-VCFT-9X-000122'
  tag rid: 'SV-VCFT-9X-000122'
  tag stig_id: 'VCFT-9X-000122'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  # Open web.xml
  xmlconf = xml("#{input('catalinaBase')}/conf/web.xml")

  # find the DefaultServlet, if there, then find the 'readOnly' parent node (init-param) and get its param-value (default is 'true' if not present)
  describe xmlconf["//*[contains(text(), 'DefaultServlet')]/parent::*/init-param[param-name = 'readOnly']/param-value"] do
    it { should be_in ['', 'true'] }
  end
end
