control 'VCFT-9X-000135' do
  title 'The VMware Cloud Foundation Operations for Logs Loginsight service must disable the debug parameter.'
  desc  'The DefaultServlet serves static resources as well as serves the directory listings (if directory listings are enabled). It is declared globally in $CATALINA_BASE/conf/web.xml and by default is configured with the "debug" parameter set to 0, which is disabled. Changing this to a value of 1 or higher sets the servlet to print debug level information. DefaultServlet debug setting must be set to 0 (disabled).'
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

    If the \"debug\" parameter is specified and is not \"0\", this is a finding.

    If the \"debug\" parameter does not exist, this is not a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/loginsight/application/3rd_party/apache-tomcat/conf/web.xml

    Navigate to all <debug> nodes that are not set to \"0\".

    Set the <param-value> to \"0\" in all <param-name>debug</param-name> nodes.

    Note: The debug setting should look like the following:

    <init-param>
          <param-name>debug</param-name>
          <param-value>0</param-value>
    </init-param>

    Restart the service with the following command:

    # systemctl restart loginsight.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag gid: 'V-VCFT-9X-000135'
  tag rid: 'SV-VCFT-9X-000135'
  tag stig_id: 'VCFT-9X-000135'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  # Open web.xml
  xmlconf = xml("#{input('catalinaBase')}/conf/web.xml")

  # find the DefaultServlet, if there, then find the 'debug' parent node (init-param) and get its param-value (default is 0 if not present)
  describe xmlconf["//*[contains(text(), 'DefaultServlet')]/parent::*/init-param[param-name = 'debug']/param-value"] do
    it { should be_in ['', '0'] }
  end
end
