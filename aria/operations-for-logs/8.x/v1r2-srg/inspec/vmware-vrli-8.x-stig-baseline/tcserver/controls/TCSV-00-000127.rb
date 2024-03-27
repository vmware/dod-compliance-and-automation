control 'TCSV-00-000127' do
  title 'tc Server must set the setCharacterEncodingFilter filter.'
  desc  "
    Invalid user input occurs when a user inserts data or characters into a hosted application's data entry field and the hosted application is unprepared to process that data. This results in unanticipated application behavior, potentially leading to an application compromise. Invalid user input is one of the primary methods employed when attempting to compromise an application.

    An attacker can also enter Unicode into hosted applications in an effort to break out of the document home or root home directory or to bypass security checks.

    As a web server, tc Server can be vulnerable to character encoding attacks if steps are not taken to mitigate the threat. tc Server uses the SetCharacterEncodingFilter to provide a layer of defense against character encoding attacks. Filters are Java objects that perform filtering tasks on either the request to a resource (a servlet or static content), or on the response from a resource, or both.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # xmllint --xpath \"//*[contains(text(), 'SetCharacterEncodingFilter')]/parent::*\" $CATALINA_BASE/conf/web.xml

    Verify that the 'setCharacterEncodingFilter' <filter> has been specified.

    If the \"setCharacterEncodingFilter\" filter has not been specified or is commented out, this is a finding.
  "
  desc 'fix', "
    Edit the $CATALINA_BASE/conf/web.xml file.

    Configure the <web-app> node with the <filter> node listed below.

    <filter>
      <filter-name>setCharacterEncodingFilter</filter-name>
      <filter-class>org.apache.catalina.filters.SetCharacterEncodingFilter</filter-class>
      <init-param>
        <param-name>encoding</param-name>
        <param-value>UTF-8</param-value>
      </init-param>
      <init-param>
        <param-name>ignore</param-name>
        <param-value>false</param-value>
      </init-param>
      <async-supported>true</async-supported>
    </filter>

    Restart the service:
    # systemctl restart loginsight.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000251-AS-000165'
  tag gid: 'V-TCSV-00-000127'
  tag rid: 'SV-TCSV-00-000127'
  tag stig_id: 'TCSV-00-000127'
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']

  # Open web.xml
  xmlconf = xml("#{input('catalinaBase')}/conf/web.xml")

  # find the SetCharacterEncodingFilter, if there, then find the 'encoding' parent node (init-param) and get its param-value
  describe xmlconf["//*[contains(text(), 'SetCharacterEncodingFilter')]/parent::*/init-param[param-name = 'encoding']/param-value"] do
    it { should eq ['UTF-8'] }
  end
end
