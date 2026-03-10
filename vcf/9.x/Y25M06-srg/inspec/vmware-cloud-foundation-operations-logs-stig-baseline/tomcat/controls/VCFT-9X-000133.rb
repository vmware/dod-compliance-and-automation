control 'VCFT-9X-000133' do
  title 'The VMware Cloud Foundation Operations for Logs Loginsight service must configure the "setCharacterEncodingFilter" filter.'
  desc  "
    Invalid user input occurs when a user inserts data or characters into a hosted application's data entry field and the hosted application is unprepared to process that data. This results in unanticipated application behavior, potentially leading to an application compromise. Invalid user input is one of the primary methods employed when attempting to compromise an application.

    An attacker can also enter Unicode characters into hosted applications in an effort to break out of the document home or root home directory or to bypass security checks. VMware uses the standard Tomcat \"SetCharacterEncodingFilter\" to provide a layer of defense against character encoding attacks. Filters are Java objects that perform filtering tasks on the request to a resource (a servlet or static content), on the response from a resource, or both.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following:

    # xmllint --xpath \"//*[contains(text(), 'setCharacterEncodingFilter')]/parent::*\" /usr/lib/loginsight/application/3rd_party/apache-tomcat/conf/web.xml

    Example result:

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

    If the \"setCharacterEncodingFilter\" filter has not been specified as shown in the example or is commented out, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/loginsight/application/3rd_party/apache-tomcat/conf/web.xml

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

    # systemctl restart loginsight.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000251-AS-000165'
  tag gid: 'V-VCFT-9X-000133'
  tag rid: 'SV-VCFT-9X-000133'
  tag stig_id: 'VCFT-9X-000133'
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']

  # Open web.xml
  xmlconf = xml("#{input('catalinaBase')}/conf/web.xml")

  describe xmlconf do
    its('/web-app/filter-mapping[filter-name="setCharacterEncodingFilter"]/url-pattern') { should cmp '/*' }
    its('/web-app/filter[filter-name="setCharacterEncodingFilter"]/filter-class') { should cmp 'org.apache.catalina.filters.SetCharacterEncodingFilter' }
    its('/web-app/filter[filter-name="setCharacterEncodingFilter"]/init-param[param-name="encoding"]/param-value') { should cmp 'UTF-8' }
    its('/web-app/filter[filter-name="setCharacterEncodingFilter"]/init-param[param-name="ignore"]/param-value') { should cmp 'true' }
  end
end
