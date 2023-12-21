control 'TCSV-00-000130' do
  title 'DefaultServlet must be set to readonly for PUT and DELETE.'
  desc  "
    The DefaultServlet is a servlet provided with tc Server. It is called when no other suitable page can be displayed to the client. It serves static resources as well as directory listings and is declared globally in $CATALINA_BASE/conf/web.xml.

    By default, tc Server behaves as if the DefaultServlet \"readOnly\" parameter is set to \"true\" (HTTP commands like PUT and DELETE are rejected). However, the \"readOnly\" parameter is not in the web.xml file by default so to ensure proper configuration and system operation, the \"readOnly\" parameter in web.xml must be created and set to \"true\".

    Ensuring the setting exists in web.xml provides assurances that the system is operating as required. Changing the readOnly parameter to false could allow clients to delete or modify static resources on the server and upload new resources.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # xmllint --xpath \"//*[contains(text(), 'DefaultServlet')]/parent::*\" $CATALINA_BASE/conf/web.xml

    If the \"readOnly\" param-value for the \"DefaultServlet\" servlet class is set to \"false\", this is a finding.

    Note: The \"readOnly\" parameter defaults to \"true\" if not present.

    EXAMPLE:
    <servlet>
      <servlet-name>default</servlet-name>
      <servlet-class>org.apache.catalina.servlets.DefaultServlet</servlet-class>
        ...
        <init-param>
          <param-name>readOnly</param-name>
          <param-value>true</param-value>
        </init-param>
        ...
    </servlet>
  "
  desc 'fix', "
    Edit the $CATALINA_BASE/conf/web.xml file.

    Ensure the \"readOnly\" param-value for the \"DefaultServlet\" servlet class is set to \"true\" if present.

    Note: The \"readOnly\" parameter defaults to \"true\" if not present.

    EXAMPLE:
    <servlet>
      <servlet-name>default</servlet-name>
      <servlet-class>org.apache.catalina.servlets.DefaultServlet</servlet-class>
        ...
        <init-param>
          <param-name>readOnly</param-name>
          <param-value>true</param-value>
        </init-param>
        ...
    </servlet>

    Restart the service:
    # systemctl restart loginsight.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000033-AS-000024'
  tag gid: 'V-TCSV-00-000130'
  tag rid: 'SV-TCSV-00-000130'
  tag stig_id: 'TCSV-00-000130'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']

  # Open web.xml
  xmlconf = xml("#{input('catalinaBase')}/conf/web.xml")

  # find the DefaultServlet, if there, then find the 'readOnly' parent node (init-param) and get its param-value (default is 'true' if not present)
  describe xmlconf["//*[contains(text(), 'DefaultServlet')]/parent::*/init-param[param-name = 'readOnly']/param-value"] do
    it { should be_in ['', 'true'] }
  end
end
