control 'VRPU-8X-000127' do
  title 'The VMware Aria Operations UI service must configure the "setCharacterEncodingFilter" filter.'
  desc  "
    Invalid user input occurs when a user inserts data or characters into a hosted application's data entry field and the hosted application is unprepared to process that data. This results in unanticipated application behavior, potentially leading to an application compromise. Invalid user input is one of the primary methods employed when attempting to compromise an application.

    An attacker can also enter Unicode into hosted applications in an effort to break out of the document home or root home directory or to bypass security checks.

    Tomcat uses the SetCharacterEncodingFilter to provide a layer of defense against character encoding attacks. Filters are Java objects that perform filtering tasks on the request to a resource (a servlet or static content), on the response from a resource, or both.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # xmllint --xpath \"//*[contains(text(), 'SetCharacterEncodingFilter')]/parent::*\" /usr/lib/vmware-vcops/tomcat-web-app/conf/web.xml

    Example result:

    <filter>
            <filter-name>setCharacterEncodingFilter</filter-name>
            <filter-class>org.apache.catalina.filters.SetCharacterEncodingFilter</filter-class>
                <init-param>
                    <param-name>encoding</param-name>
                    <param-value>UTF-8</param-value>
                </init-param>
                <init-param>
                    <param-name>ignore</param-name>
                    <param-value>true</param-value>
                </init-param>
                <async-supported>true</async-supported>
        </filter>
        <filter-mapping>
            <filter-name>setCharacterEncodingFilter</filter-name>
            <url-pattern>/*</url-pattern>
        </filter-mapping>

    If the \"setCharacterEncodingFilter\" filter has not been specified with the values shown above, this is a finding.

    Note: The \"<filter>\" and \"<filter-mapping>\" nodes may be in a different order.
  "
  desc 'fix', "
    Edit the /usr/lib/vmware-vcops/tomcat-web-app/conf/web.xml file.

    Configure the <web-app> node with the <filter> and <filter-mapping> nodes listed below.

    <filter>
            <filter-name>setCharacterEncodingFilter</filter-name>
            <filter-class>org.apache.catalina.filters.SetCharacterEncodingFilter</filter-class>
                <init-param>
                    <param-name>encoding</param-name>
                    <param-value>UTF-8</param-value>
                </init-param>
                <init-param>
                    <param-name>ignore</param-name>
                    <param-value>true</param-value>
                </init-param>
                <async-supported>true</async-supported>
        </filter>
        <filter-mapping>
            <filter-name>setCharacterEncodingFilter</filter-name>
            <url-pattern>/*</url-pattern>
        </filter-mapping>

    Restart the service:

    # systemctl restart vmware-vcops-web.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000251-AS-000165'
  tag gid: 'V-VRPU-8X-000127'
  tag rid: 'SV-VRPU-8X-000127'
  tag stig_id: 'VRPU-8X-000127'
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']
  # Open web.xml
  xmlconf = xml(input('ui-webXmlPath'))

  describe xmlconf do
    its('/web-app/filter-mapping[filter-name="setCharacterEncodingFilter"]/url-pattern') { should cmp '/*' }
    its('/web-app/filter[filter-name="setCharacterEncodingFilter"]/filter-class') { should cmp 'org.apache.catalina.filters.SetCharacterEncodingFilter' }
    its('/web-app/filter[filter-name="setCharacterEncodingFilter"]/init-param[param-name="encoding"]/param-value') { should cmp 'UTF-8' }
    its('/web-app/filter[filter-name="setCharacterEncodingFilter"]/init-param[param-name="ignore"]/param-value') { should cmp 'true' }
  end
end
