control 'VRLT-8X-000136' do
  title 'The VMware Aria Operations for Logs tc Server must disable the debug parameter.'
  desc  'The DefaultServlet serves static resources as well as serves the directory listings (if directory listings are enabled). It is declared globally in $CATALINA_BASE/conf/web.xml and by default is configured with the "debug" parameter set to 0, which is disabled. Changing this to a value of 1 or higher sets the servlet to print debug level information. DefaultServlet debug setting must be set to 0 (disabled).'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # xmllint --xpath \"//*[contains(text(), 'DefaultServlet')]/parent::*\" /usr/lib/loginsight/application/3rd_party/apache-tomcat/conf/web.xml

    If the \"debug\" param-value for the \"DefaultServlet\" servlet class does not equal 0, this is a finding.
  "
  desc 'fix', "
    Edit the /usr/lib/loginsight/application/3rd_party/apache-tomcat/conf/web.xml file.

    Examine the <init-param> elements within the <Servletclass> element.

    If the \"debug\" <param-value>element is not \"0\"\" change the \"debug\" <param-value> to read \"0\" (without quotes).

    EXAMPLE:
    <servlet>
      <servlet-name>default</servlet-name>
        ...
        <init-param>
          <param-name>debug</param-name>
          <param-value>0</param-value>
        </init-param>
        ...
    </servlet>

    Restart the service:
    # systemctl restart loginsight.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag gid: 'V-VRLT-8X-000136'
  tag rid: 'SV-VRLT-8X-000136'
  tag stig_id: 'VRLT-8X-000136'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  # Open web.xml
  xmlconf = xml("#{input('catalinaBase')}/conf/web.xml")

  # find the DefaultServlet, if there, then find the 'debug' parent node (init-param) and get its param-value (default is 0 if not present)
  describe xmlconf["//*[contains(text(), 'DefaultServlet')]/parent::*/init-param[param-name = 'debug']/param-value"] do
    it { should be_in ['', '0'] }
  end
end
