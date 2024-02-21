control 'VRLT-8X-000137' do
  title 'The VMware Aria Operations for Logs tc Server must disable the DefaultServlet directory listings parameter.'
  desc  'The DefaultServlet serves static resources as well as directory listings. It is declared globally in $CATALINA_BASE/conf/web.xml and by default is configured with the directory "listings" parameter set to disabled. If no welcome file is present and the "listings" setting is enabled, a directory listing is shown. Directory listings must be disabled.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # xmllint --xpath \"//*[contains(text(), 'DefaultServlet')]/parent::*\" /usr/lib/loginsight/application/3rd_party/apache-tomcat/conf/web.xml

    If the \"listings\" param-value for the \"DefaultServlet\" servlet class is not set to false, this is a finding.
  "
  desc 'fix', "
    Edit the /usr/lib/loginsight/application/3rd_party/apache-tomcat/conf/web.xml file.

    Examine the <init-param> elements within the <Servletclass> element, ensure the \"listings\" <param-value> is set to \"false\" (without quotes).

    EXAMPLE:
    <servlet>
      ...
      <init-param>
        <param-name>listings</param-name>
        <param-value>false</param-value>
      </init-param>
    </servlet>

    Restart the service:
    # systemctl restart loginsight.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag gid: 'V-VRLT-8X-000137'
  tag rid: 'SV-VRLT-8X-000137'
  tag stig_id: 'VRLT-8X-000137'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  # Open web.xml
  xmlconf = xml("#{input('catalinaBase')}/conf/web.xml")

  # find the DefaultServlet, if there, then find the 'listings' parent node (init-param) and get its param-value (default is 'false' if not present)
  describe xmlconf["//*[contains(text(), 'DefaultServlet')]/parent::*/init-param[param-name = 'listings']/param-value"] do
    it { should be_in ['', 'false'] }
  end
end
