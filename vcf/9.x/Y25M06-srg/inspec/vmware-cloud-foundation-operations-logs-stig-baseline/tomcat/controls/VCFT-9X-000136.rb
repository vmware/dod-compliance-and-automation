control 'VCFT-9X-000136' do
  title 'The VMware Cloud Foundation Operations for Logs Loginsight service directory listings parameter must be disabled.'
  desc  "
    Enumeration techniques, such as URL parameter manipulation, rely on being able to obtain information about the web server's directory structure by locating directories without default pages. In this scenario, the web server will display to the user a listing of the files in the directory being accessed. Ensuring that directory listing is disabled is one approach to mitigating the vulnerability.

    In Tomcat, directory listing is disabled by default but can be enabled via the \"listings\" parameter. Ensure this node is not present to have the default effect.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following:

    # xmllint --xpath \"//*[contains(text(), 'DefaultServlet')]/parent::*\" /usr/lib/loginsight/application/3rd_party/apache-tomcat/conf/web.xml

    Example result:

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
    \t<load-on-startup>1</load-on-startup>
    </servlet>

    If the \"listings\" parameter is specified and is not \"false\", this is a finding.

    If the \"listings\" parameter does not exist, this is not a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/loginsight/application/3rd_party/apache-tomcat/conf/web.xml

    Examine the <init-param> elements within the <servlet-class> element, ensure the \"listings\" <param-value> is set to \"false\" (without quotes) or removed entirely.

    The listings setting should look like the following:

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
    \t<load-on-startup>1</load-on-startup>
    </servlet>

    Restart the service with the following command:

    # systemctl restart loginsight.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag gid: 'V-VCFT-9X-000136'
  tag rid: 'SV-VCFT-9X-000136'
  tag stig_id: 'VCFT-9X-000136'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  # Open web.xml
  xmlconf = xml("#{input('catalinaBase')}/conf/web.xml")

  # find the DefaultServlet, if there, then find the 'listings' parent node (init-param) and get its param-value (default is 'false' if not present)
  describe xmlconf["//*[contains(text(), 'DefaultServlet')]/parent::*/init-param[param-name = 'listings']/param-value"] do
    it { should be_in ['', 'false'] }
  end
end
