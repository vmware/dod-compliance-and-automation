control 'VCPF-80-000127' do
  title 'The vCenter Perfcharts service must configure the "setCharacterEncodingFilter" filter.'
  desc  "
    Invalid user input occurs when a user inserts data or characters into a hosted application's data entry field and the hosted application is unprepared to process that data. This results in unanticipated application behavior, potentially leading to an application compromise. Invalid user input is one of the primary methods employed when attempting to compromise an application.

    An attacker can also enter Unicode characters into hosted applications in an effort to break out of the document home or root home directory or to bypass security checks. VMware uses the standard Tomcat \"SetCharacterEncodingFilter\" to provide a layer of defense against character encoding attacks. Filters are Java objects that perform filtering tasks on the request to a resource (a servlet or static content), on the response from a resource, or both.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # xmllint --xpath \"//*[contains(text(), 'setCharacterEncodingFilter')]/parent::*\" /usr/lib/vmware-perfcharts/tc-instance/webapps/statsreport/WEB-INF/web.xml

    Expected result:

    <filter-mapping>
      <filter-name>setCharacterEncodingFilter</filter-name>
      <url-pattern>/*</url-pattern>
    </filter-mapping>
    <filter>
      <filter-name>setCharacterEncodingFilter</filter-name>
      <filter-class>org.apache.catalina.filters.SetCharacterEncodingFilter</filter-class>
      <async-supported>true</async-supported>
      <init-param>
        <param-name>encoding</param-name>
        <param-value>UTF-8</param-value>
      </init-param>
      <init-param>
        <param-name>ignore</param-name>
        <param-value>true</param-value>
      </init-param>
    </filter>

    If the output is does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/vmware-perfcharts/tc-instance/webapps/statsreport/WEB-INF/web.xml

    Configure the <web-app> node with the child nodes listed below:

    <filter-mapping>
      <filter-name>setCharacterEncodingFilter</filter-name>
      <url-pattern>/*</url-pattern>
    </filter-mapping>

    <filter>
      <filter-name>setCharacterEncodingFilter</filter-name>
      <filter-class>org.apache.catalina.filters.SetCharacterEncodingFilter</filter-class>
      <async-supported>true</async-supported>
      <init-param>
        <param-name>encoding</param-name>
        <param-value>UTF-8</param-value>
      </init-param>
      <init-param>
        <param-name>ignore</param-name>
        <param-value>true</param-value>
      </init-param>
    </filter>

    Restart the service with the following command:

    # vmon-cli --restart perfcharts
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000251-AS-000165'
  tag gid: 'V-VCPF-80-000127'
  tag rid: 'SV-VCPF-80-000127'
  tag stig_id: 'VCPF-80-000127'
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']

  # Open web.xml
  xmlconf = xml(input('webXmlPath'))

  # added describe.one to cover "org.apache.catalina.filters.SetCharacterEncodingFilter" being on it's own line in this case
  describe.one do
    describe xmlconf do
      its('/web-app/filter-mapping[filter-name="setCharacterEncodingFilter"]/url-pattern') { should cmp '/*' }
      its('/web-app/filter[filter-name="setCharacterEncodingFilter"]/filter-class') { should cmp 'org.apache.catalina.filters.SetCharacterEncodingFilter' }
      its('/web-app/filter[filter-name="setCharacterEncodingFilter"]/init-param[param-name="encoding"]/param-value') { should cmp 'UTF-8' }
      its('/web-app/filter[filter-name="setCharacterEncodingFilter"]/init-param[param-name="ignore"]/param-value') { should cmp 'true' }
    end
    describe xmlconf do
      its('/web-app/filter-mapping[filter-name="setCharacterEncodingFilter"]/url-pattern') { should cmp '/*' }
      its('/web-app/filter[filter-name="setCharacterEncodingFilter"]/filter-class') { should match ["\n         org.apache.catalina.filters.SetCharacterEncodingFilter\n      "] }
      its('/web-app/filter[filter-name="setCharacterEncodingFilter"]/init-param[param-name="encoding"]/param-value') { should cmp 'UTF-8' }
      its('/web-app/filter[filter-name="setCharacterEncodingFilter"]/init-param[param-name="ignore"]/param-value') { should cmp 'true' }
    end
  end
end
